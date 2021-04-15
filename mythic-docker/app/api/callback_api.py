from app import mythic, db_objects, keep_logs
from sanic.response import json, text
import json as jsonlib
from app.database_models.model import (
    Callback,
    Task,
    LoadedCommands,
    PayloadCommand,
    Command,
)
from sanic_jwt.decorators import scoped, inject_user
import app.database_models.model as db_model
from sanic.exceptions import abort
from math import ceil
import requests
import base64
from sanic.log import logger
import ujson as js
import app.crypto as crypt
from app.api.task_api import get_agent_tasks
from app.api.response_api import post_agent_response
from app.api.file_api import download_agent_file
from app.api.crypto_api import staging_rsa, staging_dh
from app.api.operation_api import send_all_operations_message
import urllib.parse
from datetime import datetime
from dijkstar import Graph, find_path
from dijkstar.algorithm import NoPathError
import subprocess
from asyncio import sleep
from _collections import deque
import threading
from time import sleep as tsleep
import socket
from app.api.siem_logger import log_to_siem
import sys


@mythic.route(mythic.config["API_BASE"] + "/callbacks/", methods=["GET"])
@inject_user()
@scoped(
    ["auth:user", "auth:apitoken_user"], False
)  # user or user-level api token are ok
async def get_all_callbacks(request, user):
    if user["auth"] not in ["access_token", "apitoken"]:
        abort(
            status_code=403,
            message="Cannot access via Cookies. Use CLI or access via JS in browser",
        )
    if user["current_operation"] != "":
        query = await db_model.operation_query()
        operation = await db_objects.get(query, name=user["current_operation"])
        query = await db_model.callback_query()
        callbacks = await db_objects.execute(
            query.where(Callback.operation == operation)
        )
        return json([c.to_json() for c in callbacks])
    else:
        return json([])


# format of cached_keys:
#   {
#       "type": None or string type,
#       "enc_key": None or raw bytes of encryption key
#       "dec_key": None or raw bytes of decryption key
#   }
cached_keys = {}


@mythic.route(mythic.config["API_BASE"] + "/agent_message", methods=["GET", "POST"])
async def get_agent_message(request):
    # get the raw data first
    if request.body != b"":
        data = request.body
        # print("Body: " + str(data))
    elif len(request.cookies) != 0:
        keys = request.cookies.items()
        data = request.cookies[keys[0]]
        # print("Cookies: " + str(data))
    elif len(request.query_args) != 0:
        data = urllib.parse.unquote(request.query_args[0][1])
        # print("Query: " + str(data))
    else:
        query = await db_model.operation_query()
        operations = await db_objects.execute(query)
        for o in operations:
            await db_objects.create(
                db_model.OperationEventLog,
                operation=o,
                level="warning",
                message=f"Failed to find message in body, cookies, or query args from {request.socket} as {request.method} method with headers:\n {request.headers}",
            )
        return text("", 404)
    message, code, new_callback, msg_uuid = await parse_agent_message(data, request)
    return text(message, code)
    # return text(await parse_agent_message(data, request))


async def get_encryption_data(UUID):
    # this function tries to retrieve a cached key for a given UUID
    # if the key doesn't exist, it queries the database for the key to use if one exists
    if UUID not in cached_keys:
        # we need to look up the key to see if it exists
        try:
            # first check to see if it's some staging piece
            query = await db_model.staginginfo_query()
            staging_info = await db_objects.get(query, staging_uuid=UUID)
            cached_keys[UUID] = {
                "enc_key": base64.b64decode(staging_info.session_key),
                "type": "AES256",
                "dec_key": base64.b64decode(staging_info.session_key),
            }
            return cached_keys[UUID]
        except Exception as a:
            # if it's not a staging key, check if it's a payload uuid and get c2 profile AESPSK
            try:
                query = await db_model.payload_query()
                payload = await db_objects.get(query, uuid=UUID)
                # a payload may or may not have an AESPSK parameter/key
                try:
                    query = await db_model.payloadc2profiles_query()
                    c2_profiles = await db_objects.execute(
                        query.where(db_model.PayloadC2Profiles.payload == payload)
                    )
                    for c in c2_profiles:
                        if c.c2_profile.mythic_encrypts is False and not c.c2_profile.is_p2p:
                            cached_keys[UUID] = {
                                "enc_key": None,
                                "type": None,
                                "dec_key": None,
                            }
                            return cached_keys[UUID]
                    query = await db_model.c2profileparametersinstance_query()
                    c2_params = await db_objects.execute(
                        query.where(
                            db_model.C2ProfileParametersInstance.payload == payload
                        )
                    )
                    for cp in c2_params:
                        # loop through all of the params associated with the payload and find one with a key "AESPSK"
                        if cp.c2_profile_parameters.name == "AESPSK":
                            if cp.value == "":
                                cached_keys[UUID] = {
                                    "enc_key": None,
                                    "type": None,
                                    "dec_key": None,
                                }
                            else:
                                cached_keys[UUID] = {
                                    "enc_key": base64.b64decode(cp.value),
                                    "type": "AES256",
                                    "dec_key": base64.b64decode(cp.value),
                                }
                            return cached_keys[UUID]
                except Exception as d:
                    cached_keys[UUID] = {"enc_key": None, "type": None, "dec_key": None}
                    return cached_keys[UUID]
                if UUID not in cached_keys:
                    # if we get to this point, we found it as a payload that doesn't have an AESPSK parameter, so set it to nonne
                    cached_keys[UUID] = {"enc_key": None, "type": None, "dec_key": None}
                    return cached_keys[UUID]
            except Exception as b:
                # finally check to see if it's agent checking in
                try:
                    query = await db_model.callback_query()
                    callback = await db_objects.get(query, agent_callback_id=UUID)
                    query = await db_model.callbackc2profiles_query()
                    c2_profiles = await db_objects.execute(
                        query.where(db_model.CallbackC2Profiles.callback == callback)
                    )
                    for c in c2_profiles:
                        if c.c2_profile.mythic_encrypts is False:
                            cached_keys[UUID] = {
                                "enc_key": None,
                                "type": None,
                                "dec_key": None,
                            }
                            return cached_keys[UUID]
                    if callback.decryption_key is not None:
                        cached_keys[UUID] = {
                            "dec_key": base64.b64decode(callback.decryption_key),
                            "type": callback.encryption_type,
                            "enc_key": base64.b64decode(callback.encryption_key),
                        }
                    else:
                        cached_keys[UUID] = {
                            "enc_key": None,
                            "type": None,
                            "dec_key": None,
                        }
                    return cached_keys[UUID]
                except Exception as c:
                    logger.exception(
                        "Failed to find UUID in staging, payload's with AESPSK c2 param, or callback"
                    )
                    raise c
        return cached_keys[UUID]
    else:
        return cached_keys[UUID]


# returns a base64 encoded response message
async def parse_agent_message(data: str, request):
    new_callback = ""
    agent_uuid = ""
    try:
        decoded = base64.b64decode(data)
        # print(decoded)
    except Exception as e:
        await send_all_operations_message(f"Failed to base64 decode message: {str(data)}\nfrom {request.socket} as {request.method} method, URL {request.url} and with headers: \n{request.headers}",
                                          "warning")
        return "", 404, new_callback, agent_uuid
    try:
        UUID = decoded[:36].decode()  # first 36 characters are the UUID
        # print(UUID)
    except Exception as e:
        await send_all_operations_message(f"Failed to get UUID in first 36 bytes for base64 input: {str(data)}\nfrom {request.socket} as {request.method} method, URL {request.url} with headers: \n{request.headers}",
                                          "warning")
        return "", 404, new_callback, agent_uuid
    try:
        enc_key = await get_encryption_data(UUID)
        # print(enc_key)
    except Exception as e:
        await send_all_operations_message(f"Failed to correlate UUID to something mythic knows: {UUID}\nfrom {request.socket} as {request.method} method with headers: \n{request.headers}",
                                          "warning")
        return "", 404, new_callback, agent_uuid
    # now we have cached_keys[UUID] is the right AES key to use with this payload, now to decrypt
    decrypted = None
    try:
        # print(decoded[36:])
        # print(enc_key)
        decrypted = await crypt.decrypt_message(decoded, enc_key)
        #if enc_key["type"] is not None:
        #    if enc_key["type"] == "AES256":
        #        decrypted = await crypt.decrypt_AES256(
        #            data=decoded[36:], key=enc_key["dec_key"]
        #        )
        #        # print(decrypted)
        #    decrypted = js.loads(decrypted)
        #else:
        #    decrypted = js.loads(decoded[36:])
        #print(decrypted)
    except Exception as e:
        # print(str(e))
        if decrypted is not None:
            msg = str(decrypted)
        else:
            msg = str(decoded)
        await send_all_operations_message(f"Failed to decrypt/load message with error: {str(e)}\n {str(msg)}\nfrom {request.socket} as {request.method} method with URL {request.url} with headers: \n{request.headers}",
                                          "warning")
        return "", 404, new_callback, agent_uuid
    """
    JSON({
        "action": "", //staging-rsa, staging-dh, staging-psk, get_tasking ...
                    //  staging_info stored in db on what step in the process
        "...": ... // JSON data relating to the action
        "delegates":[
            {"UUID": base64(agentMessage from a forwarded agent)}
        ]
    })
    """
    try:

        if "action" not in decrypted:
            await send_all_operations_message("Missing 'action' in parsed JSON", "warning")
            return "", 404, new_callback, agent_uuid
        # now to parse out what we're doing, everything is decrypted at this point
        # shuttle everything out to the appropriate api files for processing
        #if keep_logs:
        #    logger.info("Agent -> Mythic: " + js.dumps(decrypted))
        # print(decrypted)
        response_data = {}
        if decrypted["action"] == "get_tasking":
            query = await db_model.callback_query()
            callback = await db_objects.get(query, agent_callback_id=UUID)
            response_data = await get_agent_tasks(decrypted, callback)
            delegates = await get_routable_messages(callback)
            if delegates is not None:
                response_data["delegates"] = delegates
            agent_uuid = UUID
        elif decrypted["action"] == "post_response":
            response_data = await post_agent_response(decrypted, UUID)
            agent_uuid = UUID
        elif decrypted["action"] == "upload":
            response_data = await download_agent_file(decrypted, UUID)
            agent_uuid = UUID
        elif decrypted["action"] == "delegate":
            # this is an agent message that is just requesting or forwarding along delegate messages
            # this is common in server_routed traffic after the first hop in the mesh
            agent_uuid = UUID
            pass
        elif decrypted["action"] == "checkin":
            if cached_keys[UUID]["type"] is not None:
                # we have encryption data when we're about to check in, so it's probably from staging
                if (
                    "encryption_key" not in decrypted
                    or decrypted["encryption_key"] == ""
                ):
                    decrypted["encryption_key"] = base64.b64encode(
                        enc_key["enc_key"]
                    ).decode()
                if (
                    "decryption_key" not in decrypted
                    or decrypted["decryption_key"] == ""
                ):
                    decrypted["decryption_key"] = base64.b64encode(
                        enc_key["dec_key"]
                    ).decode()
                if (
                    "encryption_type" not in decrypted
                    or decrypted["encryption_type"] == ""
                ):
                    decrypted["encryption_type"] = "AES256"
            response_data = await create_callback_func(decrypted, request)
            if response_data["status"] == "success":
                new_callback = response_data["id"]
        elif decrypted["action"] == "staging_rsa":
            response_data, staging_info = await staging_rsa(decrypted, UUID)
            if staging_info is not None:
                cached_keys[staging_info.staging_uuid] = {
                    "enc_key": base64.b64decode(staging_info.session_key),
                    "dec_key": base64.b64decode(staging_info.session_key),
                    "type": "AES256",
                }
            else:
                return "", 404, new_callback, agent_uuid
            # staging is it's own thing, so return here instead of following down
        elif decrypted["action"] == "staging_dh":
            response_data, staging_info = await staging_dh(decrypted, UUID)
            if staging_info is not None:
                cached_keys[staging_info.staging_uuid] = {
                    "enc_key": base64.b64decode(staging_info.session_key),
                    "dec_key": base64.b64decode(staging_info.session_key),
                    "type": "AES256",
                }
            else:
                return "", 404, new_callback, agent_uuid
        elif decrypted["action"] == "update_info":
            response_data = await update_callback(decrypted, UUID)
            agent_uuid = UUID
        else:
            await send_all_operations_message("Unknown action:" + str(decrypted["action"]), "warning")
            return "", 404, new_callback, agent_uuid
        # now that we have the right response data, format the response message
        if (
            "delegates" in decrypted
            and decrypted["delegates"] is not None
            and decrypted["delegates"] != ""
            and decrypted["delegates"] != []
        ):
            if "delegates" not in response_data:
                response_data["delegates"] = []
            for d in decrypted["delegates"]:
                # handle messages for all of the delegates
                # d is {"UUID1": agentMessage}
                for d_uuid in d:
                    # process the delegate message recursively
                    # iterate over the keys in d, typically just one
                    del_message, status, del_new_callback, del_uuid = await parse_agent_message(d[d_uuid], request)
                    if status == 200:
                        # store the response to send back
                        if del_new_callback != "":
                            # the delegate message caused a new callback, to report the changing UUID
                            response_data["delegates"].append({del_new_callback: del_message,
                                                               d_uuid: del_new_callback})
                        elif del_uuid != "" and del_uuid != d_uuid:
                            # there is no new callback
                            # the delegate is a callback (not staging) and the callback uuid != uuid in the message
                            # so send an update message with the rightful callback uuid so the agent can update
                            response_data["delegates"].append({del_uuid: del_message,
                                                               d_uuid: del_uuid})
                        else:
                            # there's no new callback and the delegate message isn't a full callback yet
                            # so just proxy through the UUID since it's in some form of staging
                            response_data["delegates"].append({d_uuid: del_message})
        #   special encryption will be handled by the appropriate stager call
        # base64 ( UID + ENC(response_data) )
        #if keep_logs:
        #    logger.info("Mythic -> Agent: " + js.dumps(response_data))
        # print(response_data)
        final_msg = await crypt.encrypt_message(response_data, enc_key, UUID)
        #if enc_key["type"] is None:
        #    return (
        #        base64.b64encode((UUID + js.dumps(response_data)).encode()).decode(),
        #        200,
        #    )
        #else:
        #    if enc_key["type"] == "AES256":
        #        enc_data = await crypt.encrypt_AES256(
        #            data=js.dumps(response_data).encode(), key=enc_key["enc_key"]
        #        )
        #        return base64.b64encode(UUID.encode() + enc_data).decode(), 200
        return final_msg, 200, new_callback, agent_uuid
    except Exception as e:
        print(sys.exc_info()[-1].tb_lineno)
        print("callback.py: " + str(e))
        await send_all_operations_message(f"Exception dealing with message: {str(decoded)}\nfrom {request.host} as {request.method} method with headers: \n{request.headers}",
                                          "warning")
        return "", 404, new_callback, agent_uuid


@mythic.route(mythic.config["API_BASE"] + "/callbacks/", methods=["POST"])
@inject_user()
@scoped(
    ["auth:user", "auth:apitoken_user"], False
)  # user or user-level api token are ok
async def create_manual_callback(request, user):
    if user["auth"] not in ["access_token", "apitoken"]:
        abort(
            status_code=403,
            message="Cannot access via Cookies. Use CLI or access via JS in browser",
        )
    if user["view_mode"] == "spectator" or user["current_operation"] == "":
        return json(
            {"status": "error", "error": "Spectators cannot create manual callbacks"}
        )
    try:
        data = request.json
        encryption = await get_encryption_data(data["uuid"])
        if encryption['type'] is None:
            data["encryption_type"] = ""
            data["encryption_key"] = None
            data["decryption_key"] = None
        else:
            data["encryption_type"] = encryption['type']
            data["encryption_key"] = base64.b64encode(encryption['enc_key']).decode()
            data["decryption_key"] = base64.b64encode(encryption['dec_key']).decode()
        return json(await create_callback_func(data, request))
    except Exception as e:
        print(e)
        return json(
            {"status": "error", "error": "failed to create callback: " + str(e)}
        )


async def create_callback_func(data, request):
    if not data:
        return {"status": "error", "error": "Data is required for POST"}
    if "user" not in data:
        return {"status": "error", "error": "User required"}
    if "host" not in data:
        return {"status": "error", "error": "Host required"}
    if "pid" not in data:
        return {"status": "error", "error": "PID required"}
    if "ip" not in data:
        return {"status": "error", "error": "IP required"}
    if "uuid" not in data:
        return {"status": "error", "error": "uuid required"}
    # Get the corresponding Payload object based on the uuid
    try:
        query = await db_model.payload_query()
        payload = await db_objects.get(query, uuid=data["uuid"])
        pcallback = payload.pcallback
    except Exception as e:
        print(e)
        return {"status": "error", "error": "payload not found by uuid"}
    if "integrity_level" not in data:
        data["integrity_level"] = 2  # default medium integrity level
    if "os" not in data:
        data["os"] = None
    if "domain" not in data:
        data["domain"] = None
    if "architecture" not in data:
        data["architecture"] = None
    if "external_ip" not in data:
        if "x-forwarded-for" in request.headers:
            data["external_ip"] = request.headers["x-forwarded-for"].split(",")[-1]
        elif "X-Forwarded-For" in request.headers:
            data["external_ip"] = request.headers["X-Forwarded-For"].split(",")[-1]
        else:
            data["external_ip"] = None
    if "extra_info" not in data:
        data["extra_info"] = ""
    try:
        if payload.operation.complete:
            await db_objects.create(
                db_model.OperationEventLog,
                operation=payload.operation,
                level="warning",
                message="Payload {} trying to checkin with data: {}".format(
                    payload.uuid, js.dumps(data)
                ),
            )
            return {"status": "error", "error": "Failed to create callback"}
        else:
            cal = await db_objects.create(
                Callback,
                user=data["user"],
                host=data["host"].upper(),
                pid=data["pid"],
                ip=data["ip"],
                description=payload.tag,
                operator=payload.operator,
                registered_payload=payload,
                pcallback=pcallback,
                operation=payload.operation,
                integrity_level=data["integrity_level"],
                os=data["os"],
                domain=data["domain"],
                architecture=data["architecture"],
                external_ip=data["external_ip"],
                extra_info=data["extra_info"],
            )
            await db_objects.create(
                db_model.OperationEventLog,
                operator=None,
                operation=payload.operation,
                message="New Callback ({}) {}@{} with pid {}".format(
                    cal.id, cal.user, cal.host, str(cal.pid)
                ),
            )
            await db_objects.create(
                db_model.PayloadOnHost,
                host=data["host"].upper(),
                payload=payload,
                operation=payload.operation,
            )
        if "encryption_type" in data:
            cal.encryption_type = data["encryption_type"]
        if "decryption_key" in data:
            cal.decryption_key = data["decryption_key"]
        if "encryption_key" in data:
            cal.encryption_key = data["encryption_key"]
        await db_objects.update(cal)
        query = await db_model.payloadcommand_query()
        payload_commands = await db_objects.execute(
            query.where(PayloadCommand.payload == payload)
        )
        # now create a loaded command for each one since they are loaded by default
        for p in payload_commands:
            await db_objects.create(
                LoadedCommands,
                command=p.command,
                version=p.version,
                callback=cal,
                operator=payload.operator,
            )
        # now create a callback2profile for each loaded c2 profile in the payload since it's there by default
        query = await db_model.payloadc2profiles_query()
        pc2profiles = await db_objects.execute(
            query.where(db_model.PayloadC2Profiles.payload == payload)
        )
        for pc2p in pc2profiles:
            if pc2p.c2_profile.is_p2p is False:
                # add in an edge to itself with the associated egress edge
                await db_objects.create(
                    db_model.CallbackGraphEdge,
                    source=cal,
                    destination=cal,
                    c2_profile=pc2p.c2_profile,
                    operation=cal.operation,
                    direction=1,
                )
            await db_objects.create(
                db_model.CallbackC2Profiles, callback=cal, c2_profile=pc2p.c2_profile
            )
            # now also save off a copy of the profile parameters
            query = await db_model.c2profileparametersinstance_query()
            instances = await db_objects.execute(
                query.where(
                    (
                        db_model.C2ProfileParametersInstance.payload
                        == cal.registered_payload
                    )
                    & (
                        db_model.C2ProfileParametersInstance.c2_profile
                        == pc2p.c2_profile
                    )
                )
            )
            for i in instances:
                await db_objects.create(
                    db_model.C2ProfileParametersInstance,
                    callback=cal,
                    c2_profile_parameters=i.c2_profile_parameters,
                    c2_profile=i.c2_profile,
                    value=i.value,
                    operation=cal.operation,
                )
        await update_graphs(cal.operation)
    except Exception as e:
        print(e)
        return {"status": "error", "error": "Failed to create callback: " + str(e)}
    status = {"status": "success"}
    await log_to_siem(cal.to_json(), mythic_object="callback_new")
    if cal.operation.webhook and cal.registered_payload.callback_alert:
        # if we have a webhook, send a message about the new callback
        try:
            if cal.integrity_level >= 3:
                int_level = "high"
            elif cal.integrity_level == 2:
                int_level = "medium"
            else:
                int_level = "low"
            message = {
                "attachments": [
                    {
                        "color": "#b366ff",
                        "blocks": [
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": "<!channel> You have a new Callback!",
                                },
                            },
                            {"type": "divider"},
                            {
                                "type": "section",
                                "fields": [
                                    {
                                        "type": "mrkdwn",
                                        "text": "*Operation:*\n{}".format(
                                            cal.operation.name
                                        ),
                                    },
                                    {
                                        "type": "mrkdwn",
                                        "text": "*IP:*\n{}".format(cal.ip),
                                    },
                                    {
                                        "type": "mrkdwn",
                                        "text": "*Callback ID:*\n{}".format(cal.id),
                                    },
                                    {
                                        "type": "mrkdwn",
                                        "text": "*Type:*\n{}".format(
                                            cal.registered_payload.payload_type.ptype
                                        ),
                                    },
                                    {
                                        "type": "mrkdwn",
                                        "text": '*Description:*\n"{}"'.format(
                                            cal.description
                                        ),
                                    },
                                    {
                                        "type": "mrkdwn",
                                        "text": "*Operator:*\n{}".format(
                                            cal.operator.username
                                        ),
                                    },
                                    {
                                        "type": "mrkdwn",
                                        "text": "*Integrity Level*\n{}".format(
                                            int_level
                                        ),
                                    },
                                ],
                            },
                        ],
                    }
                ]
            }
            response = requests.post(cal.operation.webhook, json=message)
        except Exception as e:
            logger.exception("Failed to send off webhook: " + str(e))
            print(str(e))
    for k in data:
        if k not in [
            "action",
            "user",
            "host",
            "pid",
            "ip",
            "uuid",
            "integrity_level",
            "os",
            "domain",
            "architecture",
            "external_ip",
            "encryption_type",
            "decryption_key",
            "encryption_key",
            "delegates",
            "extra_info",
        ]:
            status[k] = data[k]
    return {**status, "id": cal.agent_callback_id, "action": "checkin"}


async def load_commands_func(command_dict, callback, task):
    try:
        cquery = await db_model.command_query()
        cmd = await db_objects.get(cquery, cmd=command_dict["cmd"],
                                   payload_type=callback.registered_payload.payload_type)
        lcquery = await db_model.loadedcommands_query()
        if command_dict["action"] == "add":
            try:
                lc = await db_objects.get(lcquery, command=cmd, callback=callback)
                lc.version = cmd.version
                lc.operator = task.operator
                await db_objects.update(lc)
            except Exception as e:
                await db_objects.create(db_model.LoadedCommands,
                                             command=cmd,
                                             version=cmd.version,
                                             callback=callback,
                                             operator=task.operator)
        else:
            lc = await db_objects.get(lcquery, callback=callback, command=cmd)
            await db_objects.delete(lc)
        return {"status": "success"}
    except Exception as e:
        print(e)
        return {"status": "error", "error": str(e)}


async def update_callback(data, UUID):
    # { INPUT
    #   "action": "update_info",
    #   ... info to update, same as checkin data
    # }
    # { RESPONSE
    #   "action":  "update_info",
    #   "status":  "success",
    #   "error": "error message" (optional)
    # }
    query = await db_model.callback_query()
    cal = await db_objects.get(query, agent_callback_id=UUID)
    try:
        if UUID not in cached_keys:
            cached_keys[UUID] = {"type": None, "enc_key": None, "dec_key": None}
        if "encryption_type" in data:
            cal.encryption_type = data["encryption_type"]
            cached_keys[UUID]["type"] = cal.encryption_type
        if "encryption_key" in data:
            cal.encryption_key = data["encryption_key"]
            cached_keys[UUID]["enc_key"] = base64.b64decode(cal.encryption_key)
        if "decryption_key" in data:
            cal.decryption_key = data["decryption_key"]
            cached_keys[UUID]["dec_key"] = base64.b64decode(cal.decryption_key)
        if "user" in data:
            cal.user = data["user"]
        if "ip" in data:
            cal.ip = data["ip"]
        if "host" in data:
            cal.host = data["host"].upper()
        if "external_ip" in data:
            cal.external_ip = data["external_ip"]
        if "integrity_level" in data:
            cal.integrity_level = data["integrity_level"]
        if "domain" in data:
            cal.domain = data["domain"]
        if "extra_info" in data:
            cal.extra_info = data["extra_info"]
        if "os" in data:
            cal.os = data["os"]
        if "architecture" in data:
            cal.architecture = data["architecture"]
        if "pid" in data:
            cal.pid = data["pid"]
        await db_objects.update(cal)
        return {"action": "update_info", "status": "success"}
    except Exception as e:
        print("error in callback update function")
        print(str(e))
        return {"action": "update_info", "status": "error", "error": str(e)}


# https://pypi.org/project/Dijkstar/
current_graphs = {}


async def get_routable_messages(requester):
    # are there any messages sitting in the database in the "submitted" stage that have routes from the requester
    # 1. get all CallbackGraphEdge entries that have an end_timestamp of Null (they're still active)
    # 2. feed into dijkstar and do shortest path
    # 3. for each element in the shortest path, see if there's any tasking stored
    # 4.   if there's tasking, wrap it up in a message:
    #        content is the same of that of a "get_tasking" reply with a a -1 request
    delegates = []
    operation = requester.operation
    if operation.name not in current_graphs:
        await update_graphs(operation)
    if current_graphs[operation.name].edge_count == 0:
        return None  # graph for this operation has no edges
    query = await db_model.task_query()
    submitted_tasks = await db_objects.execute(
        query.where(
            (db_model.Task.status == "submitted")
            & (db_model.Callback.operation == operation)
        )
    )
    # print(len(submitted_tasks))
    # this is a mapping of UUID to list of tasks that it'll get
    temp_callback_tasks = {}
    for t in submitted_tasks:
        # print(t.to_json())
        try:
            path = find_path(current_graphs[operation.name], requester, t.callback)
        except NoPathError:
            # print("No path from {} to {}".format(requester.id, t.callback.id))
            continue
        if len(path.nodes) > 1 and path.nodes[-1] != requester:
            # this means we have some sort of path longer than 1
            # make a tasking message for this
            # print(t.to_json())
            if path.nodes[-1].agent_callback_id in temp_callback_tasks:
                temp_callback_tasks[path.nodes[-1].agent_callback_id]["tasks"].append(t)
            else:
                temp_callback_tasks[path.nodes[-1].agent_callback_id] = {
                    "tasks": [t],
                    "path": path.nodes[::-1],
                }
    # now actually construct the tasks
    for k, v in temp_callback_tasks.items():
        # print(k)
        # print(v)
        tasks = []
        for t in v["tasks"]:
            t.status = "processing"
            t.status_timestamp_processing = datetime.utcnow()
            t.timestamp = t.status_timestamp_processing
            await db_objects.update(t)
            tasks.append(
                {
                    "command": t.command.cmd,
                    "parameters": t.params,
                    "id": t.agent_task_id,
                    "timestamp": t.timestamp.timestamp(),
                }
            )
        # now that we have all the tasks we're going to send, make the message
        message = {"action": "get_tasking", "tasks": tasks}
        # now wrap this message up like it's going to be sent out, first level is just normal
        enc_key = await get_encryption_data(v["path"][0].agent_callback_id)
        if enc_key['type'] is None:
            message = {
                v["path"][0]
                .agent_callback_id: base64.b64encode(
                    (v["path"][0].agent_callback_id + js.dumps(message)).encode()
                )
                .decode()
            }
        else:
            enc_data = await crypt.encrypt_AES256(
                data=js.dumps(message).encode(), key=enc_key['enc_key']
            )
            message = {
                v["path"][0]
                .agent_callback_id: base64.b64encode(
                    v["path"][0].agent_callback_id.encode() + enc_data
                )
                .decode()
            }
        # for every other agent in the path though, their action is a delegate message
        # we don't need to do this wrapping for the last in the list since that's the egress node asking for tasking
        for cal in v["path"][1:-1]:
            message = {"action": "get_tasking", "tasks": [], "delegates": [message]}
            enc_key = await get_encryption_data(cal.agent_callback_id)
            if enc_key['type'] is None:
                message = {
                    cal.agent_callback_id: base64.b64encode(
                        (cal.agent_callback_id + js.dumps(message)).encode()
                    ).decode()
                }
            else:
                enc_data = await crypt.encrypt_AES256(
                    data=js.dumps(message).encode(), key=enc_key['enc_key']
                )
                message = {
                    cal.agent_callback_id: base64.b64encode(
                        cal.agent_callback_id.encode() + enc_data
                    ).decode()
                }
        delegates.append(message)
    # print(delegates)
    if len(delegates) == 0:
        return None
    else:
        return delegates


async def update_graphs(operation):
    try:
        query = await db_model.callbackgraphedge_query()
        available_edges = await db_objects.execute(
            query.where(
                (db_model.CallbackGraphEdge.operation == operation)
                & (db_model.CallbackGraphEdge.end_timestamp == None)
            )
        )
        temp = Graph()
        # dijkstra is directed, so if we have a bidirectional connection (type 3) account for that as well
        for e in available_edges:
            if e.source == e.destination:
                temp.add_edge(e.source, e.c2_profile, 1)
            elif e.direction == 1:
                temp.add_edge(e.source, e.destination, 1)
            elif e.direction == 2:
                temp.add_edge(e.destination, e.source, 1)
            elif e.direction == 3:
                temp.add_edge(e.source, e.destination, 1)
                temp.add_edge(e.destination, e.source, 1)
        query = await db_model.c2profile_query()
        profiles = await db_objects.execute(
            query.where(db_model.C2Profile.is_p2p == False)
        )
        for p in profiles:
            temp.add_edge(p, "Mythic", 1)
        current_graphs[operation.name] = temp
    except Exception as e:
        print(str(e))
        return


current_non_directed_graphs = {}


async def update_non_directed_graphs(operation):
    try:
        query = await db_model.callbackgraphedge_query()
        available_edges = await db_objects.execute(
            query.where(
                (db_model.CallbackGraphEdge.operation == operation)
                & (db_model.CallbackGraphEdge.end_timestamp == None)
            )
        )
        temp = Graph()
        # dijkstra is directed, so if we have a bidirectional connection (type 3) account for that as well
        for e in available_edges:
            if e.source == e.destination:
                temp.add_edge(e.source, e.c2_profile, 1)
                temp.add_edge(e.c2_profile, e.source, 1)
            else:
                temp.add_edge(e.source, e.destination, 1)
                temp.add_edge(e.destination, e.source, 1)
        query = await db_model.c2profile_query()
        profiles = await db_objects.execute(
            query.where(db_model.C2Profile.is_p2p == False)
        )
        for p in profiles:
            temp.add_edge(p, "Mythic", 1)
            temp.add_edge("Mythic", p, 1)
        current_non_directed_graphs[operation.name] = temp
    except Exception as e:
        print(str(e))
        return


async def add_non_directed_graphs(e):
    if e.source.operation.name not in current_non_directed_graphs:
        current_non_directed_graphs[e.source.operation.name] = Graph()
    try:
        if e.source == e.destination:
            current_non_directed_graphs[e.source.operation.name].add_edge(
                e.source, e.c2_profile, 1
            )
            current_non_directed_graphs[e.source.operation.name].add_edge(
                e.c2_profile, e.source, 1
            )
        else:
            current_non_directed_graphs[e.source.operation.name].add_edge(
                e.source, e.destination, 1
            )
            current_non_directed_graphs[e.source.operation.name].add_edge(
                e.destination, e.source, 1
            )
    except Exception as e:
        print(str(e))
        return


async def remove_non_directed_graphs(e):
    if e.source.operation.name not in current_non_directed_graphs:
        current_non_directed_graphs[e.source.operation.name] = Graph()
    try:
        if e.source == e.destination:
            current_non_directed_graphs[e.source.operation.name].remove_edge(
                e.source, e.c2_profile
            )
            current_non_directed_graphs[e.source.operation.name].remove_edge(
                e.c2_profile, e.source
            )
        else:
            current_non_directed_graphs[e.source.operation.name].remove_edge(
                e.source, e.destination
            )
            current_non_directed_graphs[e.source.operation.name].remove_edge(
                e.destination, e.source
            )
    except Exception as e:
        print(str(e))
        return


@mythic.route(
    mythic.config["API_BASE"] + "/callbacks/edges/<id:int>", methods=["DELETE"]
)
@inject_user()
@scoped(
    ["auth:user", "auth:apitoken_user"], False
)  # user or user-level api token are ok
async def remove_graph_edge(request, id, user):
    if user["auth"] not in ["access_token", "apitoken"]:
        abort(
            status_code=403,
            message="Cannot access via Cookies. Use CLI or access via JS in browser",
        )
    if user["view_mode"] == "spectator" or user["current_operation"] == "":
        return json(
            {"status": "error", "error": "Spectators cannot remove graph edges"}
        )
    try:
        query = await db_model.operation_query()
        operation = await db_objects.get(query, name=user["current_operation"])
        edge_query = await db_model.callbackgraphedge_query()
        edge = await db_objects.get(edge_query, id=id, operation=operation)
        edge.end_timestamp = datetime.utcnow()
        await db_objects.update(edge)
        return json({"status": "success"})
    except Exception as e:
        return json({"status": "error", "error": "Failed to update: " + str(e)})


cached_rportfwd = {}
callback_port = {}

async def start_rportfwd(port: int, rport: int, rip: str, callback: Callback, task: Task):
    try:
        if port in callback_port:
            return {"status": "error", "error": "Port Forward already started on that port"}
    except:
        # we're not using this port, so we can use it
        pass
    print("starting rportfwd")
    server_address = ('0.0.0.0', port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(server_address)
    if (callback.id not in cached_rportfwd):
        cached_rportfwd[callback.id] = {}
    cached_rportfwd[callback.id][port] = {
        "connections": [],
        #list of dictionary: connection, thread_read, queue
        "thread_handle": threading.Thread(
            target=thread_handle_connections,
            kwargs={"port": port,"sock": sock, "callback_id": callback.id},
        ),
        "state": 1,
        "sock":sock,
        "rport": rport,
        "rip": rip,
    }
    callback_port[port] = callback
    #callback.port = port
    #callback.rportfwd_task = task
    cached_rportfwd[callback.id][port]["thread_handle"].start()
    return {"status": "success"}

async def stop_rportfwd(port: int, callback: Callback, task: Task):
    if callback.id in cached_rportfwd:
        if port in cached_rportfwd[callback.id]:
            cached_rportfwd[callback.id][port]["state"] = 0
        for connection in cached_rportfwd[callback.id][port]["connections"]:
            try:
                connection["connection"].shutdown(socket.SHUT_RDWR)
                connection["connection"].close()
            except:
                pass
        try:
            cached_rportfwd[callback.id][port]["sock"].shutdown(socket.SHUT_RDWR)
            cached_rportfwd[callback.id][port]["sock"].close()
        except:
            pass
        del cached_rportfwd[callback.id][port]
        if bool(cached_rportfwd[callback.id]) == False:
            del cached_rportfwd[callback.id]

        del callback_port[port]

    try:
        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "error": "failed to find socks instance: " + str(e)}


async def flush_rportfwd(callback: Callback, task: Task):
    try:
        if callback.id in cached_rportfwd:
            for port in cached_rportfwd[callback.id]:
                cached_rportfwd[callback.id][port]["state"] = 0
                try:
                    for connection in cached_rportfwd[callback.id][port]["connections"]:
                        try:
                            connection["connection"].shutdown(socket.SHUT_RDWR)
                            connection["connection"].close()
                        except:
                            pass
                    cached_rportfwd[callback.id][port]["sock"].shutdown(socket.SHUT_RDWR)
                    cached_rportfwd[callback.id][port]["sock"].close()
                    del callback_port[port]
                except:
                    pass
        try:
            del cached_rportfwd[callback.id]
        except:
            pass

        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "error": "failed to find rportfwd instance: " + str(e)}


def thread_handle_connections(port: int,sock: socket, callback_id: int) -> None:
    sock.listen(1)
    id = 0

    try:
        while cached_rportfwd[callback_id][port]["state"] == 1:
            connection, client_address = sock.accept()
            conn_sock = {
                "connection": connection,
                "thread_read": threading.Thread(
                    target=thread_read_rportfwd,
                    kwargs={"port": port,"connection": connection, "id": id, "callback_id": callback_id},
                ),
                "queue": deque(),
            }
            cached_rportfwd[callback_id][port]["connections"].append(conn_sock)
            cached_rportfwd[callback_id][port]["connections"][id]["thread_read"].start()
            id = id + 1
    except:
        pass
        #connection closd



def thread_read_rportfwd(port: int,connection: socket, id: int, callback_id: int) -> None:
    try:
        data = connection.recv(8192)
        while (data and cached_rportfwd[callback_id][port]["state"] == 1):
            data = base64.b64encode(data)
            data = data.decode('ascii')
            cached_rportfwd[callback_id][port]["connections"][id]["queue"].append(data)
            data = connection.recv(8192)
                # print("now trying to read in: {} bytes".format(str(size)))
    except Exception as e:
            #print("*" * 10 + "Got exception from reading socket data" + "*" * 10)
        try:
            connection.close()
        except:
            pass
        tsleep(1)


async def get_rportfwd_data(callback: Callback):
    default_struct = []
    if (bool(cached_rportfwd) == False):
        return default_struct
    dict_conn = {}
    if callback.id in cached_rportfwd:
        for port in cached_rportfwd[callback.id]:
            id = 0
            rport = cached_rportfwd[callback.id][port]["rport"]
            rip = cached_rportfwd[callback.id][port]["rip"]
            dict_conn[str(port)] = {}
            dict_conn[str(port)][str(rport)] = {}
            dict_conn[str(port)][str(rport)][str(rip)] = {}
            if len(cached_rportfwd[callback.id][port]["connections"]) > 0:
                for connection in cached_rportfwd[callback.id][port]["connections"]:
                    deq = 0
                    dict_conn[str(port)][str(rport)][str(rip)][str(id)] = []
                    while (len(cached_rportfwd[callback.id][port]["connections"][id]["queue"]) > 0):
                        try:
                            dict_conn[str(port)][str(rport)][str(rip)][str(id)].append(connection["queue"].popleft())
                        except:
                            pass
                    #deque the rest for the next time, this avoids hanging connections
                    id = id+1
        
    # if len(data) > 0:
    # print("******* SENDING THE FOLLOWING TO THE AGENT ******")
    # print(data)
    #json data in format:
    # {"9090":{"445":{"10.0.0.1":{
    #           "1":["base64Str","base64Str","base64Str"]
    #           "2":["base64Str","base64Str","base64Str"]
    #           "3":["base64Str","base64Str","base64Str"]
    #         }}}
    #  "9091":{"3389":{"10.0.0.2":{
    #           "1":["base64Str","base64Str","base64Str"]
    #           "2":["base64Str","base64Str","base64Str"]
    #           "3":["base64Str","base64Str","base64Str"]
    #         }}}
    #   }
    #}
    if(bool(dict_conn) == False):
        return default_struct
    dict_conn = jsonlib.dumps(dict_conn)
    default_struct.append(dict_conn)
    return default_struct

async def send_rportfwds_data(data, callback: Callback):
    #data = agent_message["rportfwd"]
    data = data[0]
    id = 0
    try:
        for data_key in data:
            for port in data[data_key]:
                for rport in data[data_key][port]:
                    for rip in data[data_key][port][rport]:
                        id = 0
                        for i in data[data_key][port][rport][rip]:
                            print(i)
                            total_msg = b''
                            for d in data[data_key][port][rport][rip][i]:
                                if callback.id in cached_rportfwd.keys():
                                    msg = base64.b64decode(d)
                                    cached_rportfwd[callback.id][int(port)]["connections"][int(i)]["connection"].sendall(msg)
                                                                    #else:
                                    #print("****** NO CACHED PORTFWD, MUST BE CLOSED *******")
        return {"status": "success"}
    except Exception as e:
        #print("******** EXCEPTION IN SEND RPORTFWD DATA *****\n{}".format(str(e)))
        print(str(e))
        return {"status": "error", "error": str(e)}



cached_socks = {}

async def start_socks(port: int, callback: Callback, task: Task):
    # print("starting socks")
    try:
        query = await db_model.callback_query()
        socks_instance = await db_objects.get(
            query.where(
                (db_model.Callback.port == port) | (db_model.Callback.port + 1 == port)
            )
        )
        return {"status": "error", "error": "socks already started on that port"}
    except:
        # we're not using this port, so we can use it
        pass

    # now actually start the binary
    # f = open("socks_logs.txt", "w")
    process = subprocess.Popen(
        ["./socks_server/goserver", str(port), str(port + 1)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    await sleep(3)
    process.poll()
    if process.returncode is not None:
        stdout, stderr = process.communicate()
        message = (
            "Failed to start proxy on port "
            + str(port)
            + ". Got error code: "
            + str(process.returncode)
            + "\nstdout: "
            + str(stdout)
            + "\nstderr: "
            + str(stderr)
        )
        await db_objects.create(
            db_model.OperationEventLog,
            operator=task.operator,
            operation=callback.operation,
            message=message,
            level="error",
        )
        return {"status": "error", "error": "failed to start socks proxy"}
    callback.port = port
    callback.socks_task = task
    await db_objects.update(callback)
    cached_socks[callback.id] = {
        "process": process,
        "queue": deque(),
        "thread": threading.Thread(
            target=thread_read_socks,
            kwargs={"port": port + 1, "callback_id": callback.id},
        ),
    }
    cached_socks[callback.id]["thread"].start()
    await db_objects.create(
        db_model.OperationEventLog,
        operator=task.operator,
        operation=callback.operation,
        message="Started socks proxy on port {} in callback {}".format(
            str(port), str(callback.id)
        ),
    )
    # print("started socks")
    return {"status": "success"}


async def stop_socks(callback: Callback, operator):
    if callback.id in cached_socks:
        try:
            cached_socks[callback.id]["thread"].exit()
        except:
            pass
        try:
            cached_socks[callback.id]["socket"].close()
        except:
            pass
        try:
            cached_socks[callback.id]["process"].terminate()
        except:
            pass

        del cached_socks[callback.id]
    try:
        port = callback.port
        callback.port = None
        await db_objects.update(callback)
        await db_objects.create(
            db_model.OperationEventLog,
            operator=operator,
            operation=callback.operation,
            message="Stopped rportfwd proxy on port {} in callback {}".format(
                str(port), str(callback.id)
            ),
        )
        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "error": "failed to find rportfwd instance: " + str(e)}


async def start_all_socks_after_restart():
    query = await db_model.callback_query()
    socks_instance = await db_objects.execute(
        query.where(db_model.Callback.port != None)
    )
    for s in socks_instance:
        # now actually start the binary
        # f = open("socks_logs.txt", "w")
        process = subprocess.Popen(
            ["./socks_server/goserver", str(s.port), str(s.port + 1)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        await sleep(3)
        process.poll()
        if process.returncode is not None:
            stdout, stderr = process.communicate()
            message = (
                "Failed to start proxy on port "
                + str(s.port)
                + ". Got error code: "
                + str(process.returncode)
                + "\nstdout: "
                + str(stdout)
                + "\nstderr: "
                + str(stderr)
            )
            await db_objects.create(
                db_model.OperationEventLog,
                operator=s.socks_task.operator,
                operation=s.operation,
                message=message,
                level="error",
            )
        cached_socks[s.id] = {
            "process": process,
            "queue": deque(),
            "thread": threading.Thread(
                target=thread_read_socks,
                kwargs={"port": s.port + 1, "callback_id": s.id},
            ),
        }
        cached_socks[s.id]["thread"].start()
        await db_objects.create(
            db_model.OperationEventLog,
            operator=s.socks_task.operator,
            operation=s.operation,
            message="Started socks proxy on port {} in callback {}".format(
                str(s.port), str(s.id)
            ),
        )


async def send_socks_data(data, callback: Callback):
    try:
        total_msg = b''
        for d in data:
            if callback.id in cached_socks:
                msg = js.dumps(d).encode()
                #print("******* SENDING DATA BACK TO PROXYCHAINS *****")
                #print(msg)
                msg = int.to_bytes(len(msg), 4, "big") + msg
                total_msg += msg
                # cached_socks[callback.id]['socket'].sendall(int.to_bytes(len(msg), 4, "big"))
            #else:
                #print("****** NO CACHED SOCKS, MUST BE CLOSED *******")
        cached_socks[callback.id]["socket"].sendall(total_msg)
        return {"status": "success"}
    except Exception as e:
        #print("******** EXCEPTION IN SEND SOCKS DATA *****\n{}".format(str(e)))
        return {"status": "error", "error": str(e)}


async def get_socks_data(callback: Callback):
    data = []
    if callback.port is not None:
        if callback.id in cached_socks:
            while True:
                try:
                    data.append(cached_socks[callback.id]["queue"].popleft())
                    #print("Just got socks data to give to agent")
                except:
                    break
    #if len(data) > 0:
        #print("******* SENDING THE FOLLOWING TO THE AGENT ******")
        #print(data)
    return data


def thread_read_socks(port: int, callback_id: int) -> None:
    # print(port)
    # print(callback_id)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect the socket to the port where the server is listening
    server_address = ("localhost", port)
    sock.connect(server_address)
    # sock.settimeout(2)
    try:
        cached_socks[callback_id]["socket"] = sock
    except Exception as e:
        sock.close()
        return
    while True:
        #print("in thread loop")
        try:
            # print("about to get size")
            #need to parse size
            size = sock.recv(4)
            if len(size) == 4:
                size = int.from_bytes(size, "big")
            elif len(size) == 0:
                tsleep(1)
                continue
            # print("now trying to read in: {} bytes".format(str(size)))
            msg = sock.recv(size)
            try:
                cached_socks[callback_id]["queue"].append(js.loads(msg.decode()))
                #print("just read from proxychains and added to queue for agent to pick up")
            except Exception as d:
                if callback_id not in cached_socks:
                    #print("*" * 10 + "Got closing socket" + "*" * 10)
                    sock.close()
                    #print("thread exiting")
                    return
        except Exception as e:
            #print("*" * 10 + "Got exception from reading socket data" + "*" * 10)
            #print(e)
            if callback_id not in cached_socks:
                #print("*" * 10 + "Got closing socket" + "*" * 10)
                sock.close()
                #print("thread exiting")
                return
            tsleep(1)


@mythic.route(mythic.config["API_BASE"] + "/callbacks/<id:int>", methods=["GET"])
@inject_user()
@scoped(
    ["auth:user", "auth:apitoken_user"], False
)  # user or user-level api token are ok
async def get_one_callback(request, id, user):
    if user["auth"] not in ["access_token", "apitoken"]:
        abort(
            status_code=403,
            message="Cannot access via Cookies. Use CLI or access via JS in browser",
        )
    try:
        if user["current_operation"] == "":
            return json({"status": "error", "error": "must be part of an operation"})
        query = await db_model.operation_query()
        operation = await db_objects.get(query, name=user["current_operation"])
        query = await db_model.callback_query()
        callback = await db_objects.get(query, id=id, operation=operation)
        return_json = callback.to_json()
        query = await db_model.loadedcommands_query()
        loaded_commands = await db_objects.execute(
            query.where(LoadedCommands.callback == callback)
        )
        return_json["loaded_commands"] = [
            {
                "command": lc.command.cmd,
                "version": lc.version,
                "mythic_version": lc.command.version,
            }
            for lc in loaded_commands
        ]
        query = await db_model.callbackc2profiles_query()
        callbackc2profiles = await db_objects.execute(
            query.where(db_model.CallbackC2Profiles.callback == callback)
        )
        c2_profiles_info = {}
        for c2p in callbackc2profiles:
            query = await db_model.c2profileparametersinstance_query()
            c2_profile_params = await db_objects.execute(
                query.where(
                    (db_model.C2ProfileParametersInstance.callback == callback)
                    & (
                        db_model.C2ProfileParametersInstance.c2_profile
                        == c2p.c2_profile
                    )
                )
            )
            params = [p.to_json() for p in c2_profile_params]
            c2_profiles_info[c2p.c2_profile.name] = params
        return_json["c2_profiles"] = c2_profiles_info
        query = await db_model.buildparameterinstance_query()
        build_parameters = await db_objects.execute(
            query.where(
                db_model.BuildParameterInstance.payload == callback.registered_payload
            )
        )
        build_params = [t.to_json() for t in build_parameters]
        return_json["build_parameters"] = build_params
        return_json["payload_uuid"] = callback.registered_payload.uuid
        return_json["payload_name"] = callback.registered_payload.file_id.filename
        return_json["status"] = "success"
        paths = await path_to_callback(callback)
        return_json["path"] = [str(p) for p in paths]
        return json(return_json)
    except Exception as e:
        print(e)
        return json(
            {"status": "error", "error": "failed to get callback: " + str(e)}, 200
        )


@mythic.route(mythic.config["API_BASE"] + "/callbacks/<id:int>", methods=["PUT"])
@inject_user()
@scoped(["auth:user", "auth:apitoken_user", "auth:apitoken_c2"], False)
async def update_callback_web(request, id, user):
    if user["auth"] not in ["access_token", "apitoken"]:
        abort(
            status_code=403,
            message="Cannot access via Cookies. Use CLI or access via JS in browser",
        )
    if user["view_mode"] == "spectator" or user["current_operation"] == "":
        return json({"status": "error", "error": "Spectators cannot update callbacks"})
    data = request.json
    try:
        query = await db_model.operation_query()
        operation = await db_objects.get(query, name=user["current_operation"])
        query = await db_model.callback_query()
        cal = await db_objects.get(query, id=id, operation=operation)
        if "description" in data:
            if data["description"] == "reset":
                # set the description back to what it was from the payload
                cal.description = cal.registered_payload.tag
            else:
                cal.description = data["description"]
        if "active" in data:
            if data["active"] == "true":
                if not cal.active:
                    c2_query = await db_model.callbackc2profiles_query()
                    c2profiles = await db_objects.execute(
                        c2_query.where(db_model.CallbackC2Profiles.callback == cal)
                    )
                    for c2 in c2profiles:
                        if not c2.c2_profile.is_p2p:
                            try:
                                edge = await db_objects.get(
                                    db_model.CallbackGraphEdge,
                                    source=cal,
                                    destination=cal,
                                    c2_profile=c2.c2_profile,
                                    direction=1,
                                    end_timestamp=None,
                                    operation=cal.operation,
                                )
                            except Exception as d:
                                print(d)
                                edge = await db_objects.create(
                                    db_model.CallbackGraphEdge,
                                    source=cal,
                                    destination=cal,
                                    c2_profile=c2.c2_profile,
                                    direction=1,
                                    end_timestamp=None,
                                    operation=cal.operation,
                                )
                                await add_non_directed_graphs(edge)
                                await add_directed_graphs(edge)
                    cal.active = True
            elif data["active"] == "false":
                if cal.active:
                    edge_query = await db_model.callbackgraphedge_query()
                    try:
                        edges = await db_objects.execute(
                            edge_query.where(
                                (db_model.CallbackGraphEdge.source == cal)
                                & (db_model.CallbackGraphEdge.destination == cal)
                                & (db_model.CallbackGraphEdge.end_timestamp == None)
                                & (
                                    db_model.CallbackGraphEdge.operation
                                    == cal.operation
                                )
                            )
                        )
                        for edge in edges:
                            if not edge.c2_profile.is_p2p:
                                edge.end_timestamp = datetime.utcnow()
                                await db_objects.update(edge)
                                await remove_non_directed_graphs(edge)
                                await remove_directed_graphs(edge)
                    except Exception as d:
                        print(
                            "error trying to add end-timestamps to edges when going inactive"
                        )
                        print(d)
                cal.active = False
        if "encryption_type" in data:
            cal.encryption_type = data["encryption_type"]
        if "encryption_key" in data:
            cal.encryption_key = data["encryption_key"]
        if "decryption_key" in data:
            cal.decryption_key = data["decryption_key"]
        if "locked" in data:
            if cal.locked and not data["locked"]:
                # currently locked and trying to unlock, must be admin, admin of that operation, or the user that did it
                if (
                    user["admin"]
                    or cal.operation.name in user["admin_operations"]
                    or user["username"] == cal.locked_operator.username
                ):
                    cal.locked = False
                    cal.locked_operator = None
                else:
                    await db_objects.update(cal)
                    return json(
                        {"status": "error", "error": "Not authorized to unlock"}
                    )
            elif not cal.locked and data["locked"]:
                # currently unlocked and wanting to lock it
                if (
                    user["admin"]
                    or cal.operation.name in user["operations"]
                    or cal.operation.name in user["admin_operations"]
                ):
                    cal.locked = True
                    query = await db_model.operator_query()
                    operator = await db_objects.get(query, username=user["username"])
                    cal.locked_operator = operator
                else:
                    await db_objects.update(cal)
                    return json({"status": "error", "error": "Not authorized to lock"})
        if "parent" in data:
            try:
                if data["parent"] == -1:
                    # this means to remove the current parent
                    cal.pcallback = None
                else:
                    query = await db_model.callback_query()
                    parent = await db_objects.get(
                        query, id=data["parent"], operation=operation
                    )
                    if parent.id == cal.id:
                        return json(
                            {"status": "error", "error": "cannot set parent = child"}
                        )
                    cal.pcallback = parent
            except Exception as e:
                return json(
                    {
                        "status": "error",
                        "error": "failed to set parent callback: " + str(e),
                    }
                )
        await db_objects.update(cal)
        success = {"status": "success"}
        updated_cal = cal.to_json()
        return json({**success, **updated_cal})
    except Exception as e:
        print(e)
        return json(
            {"status": "error", "error": "failed to update callback: " + str(e)}
        )


@mythic.route(mythic.config["API_BASE"] + "/callbacks/<id:int>", methods=["DELETE"])
@inject_user()
@scoped(
    ["auth:user", "auth:apitoken_user"], False
)  # user or user-level api token are ok
async def remove_callback(request, id, user):
    if user["auth"] not in ["access_token", "apitoken"]:
        abort(
            status_code=403,
            message="Cannot access via Cookies. Use CLI or access via JS in browser",
        )
    if user["view_mode"] == "spectator" or user["current_operation"] == "":
        return json(
            {"status": "error", "error": "Spectators cannot make callbacks inactive"}
        )
    try:
        query = await db_model.callback_query()
        cal = await db_objects.get(query, id=id)
        if user["admin"] or cal.operation.name in user["operations"]:
            cal.active = False
            await db_objects.update(cal)
            success = {"status": "success"}
            deleted_cal = cal.to_json()
            return json({**success, **deleted_cal})
        else:
            return json(
                {
                    "status": "error",
                    "error": "must be an admin or part of that operation to mark it as no longer active",
                }
            )
    except Exception as e:
        print(e)
        return json(
            {"status": "error", "error": "failed to delete callback: " + str(e)}
        )


@mythic.route(
    mythic.config["API_BASE"] + "/callbacks/<id:int>/all_tasking", methods=["GET"]
)
@inject_user()
@scoped(
    ["auth:user", "auth:apitoken_user"], False
)  # user or user-level api token are ok
async def callbacks_get_all_tasking(request, user, id):
    if user["auth"] not in ["access_token", "apitoken"]:
        abort(
            status_code=403,
            message="Cannot access via Cookies. Use CLI or access via JS in browser",
        )
    # Get all of the tasks and responses so far for the specified agent
    try:
        query = await db_model.operation_query()
        operation = await db_objects.get(query, name=user["current_operation"])
        query = await db_model.callback_query()
        callback = await db_objects.get(query, id=id, operation=operation)
        cb_json = callback.to_json()
        cb_json["tasks"] = []
        query = await db_model.task_query()
        tasks = await db_objects.prefetch(
            query.where(Task.callback == callback).order_by(Task.id), Command.select()
        )
        for t in tasks:
            cb_json["tasks"].append({**t.to_json()})
        return json({"status": "success", **cb_json})
    except Exception as e:
        print(e)
        return json({"status": "error", "error": str(e)})


@mythic.route(mythic.config["API_BASE"] + "/callbacks/<id:int>/keys", methods=["GET"])
@inject_user()
@scoped(["auth:user", "auth:apitoken_user", "auth:apitoken_c2"], False)
async def get_callback_keys(request, user, id):
    if user["auth"] not in ["access_token", "apitoken"]:
        abort(
            status_code=403,
            message="Cannot access via Cookies. Use CLI or access via JS in browser",
        )
    if user["view_mode"] == "spectator" or user["current_operation"] == "":
        return json({"status": "error", "error": "Spectators cannot get callback keys"})
    try:
        query = await db_model.operation_query()
        operation = await db_objects.get(query, name=user["current_operation"])
        query = await db_model.callback_query()
        callback = await db_objects.get(query, id=id, operation=operation)
    except Exception as e:
        print(e)
        return json({"status": "error", "error": "failed to find callback"})
    encryption_type = callback.encryption_type if callback.encryption_type else ""
    decryption_key = callback.decryption_key if callback.decryption_key else ""
    encryption_key = callback.encryption_key if callback.encryption_key else ""
    return json(
        {
            "status": "success",
            "encryption_type": encryption_type,
            "decryption_key": decryption_key,
            "encryption_key": encryption_key,
        }
    )


@mythic.route(
    mythic.config["API_BASE"] + "/callbacks/<page:int>/<size:int>", methods=["GET"]
)
@inject_user()
@scoped(
    ["auth:user", "auth:apitoken_user"], False
)  # user or user-level api token are ok
async def get_pageinate_callbacks(request, user, page, size):
    if user["auth"] not in ["access_token", "apitoken"]:
        abort(
            status_code=403,
            message="Cannot access via Cookies. Use CLI or access via JS in browser",
        )
    # get all of the artifact tasks for the current operation
    if page <= 0 or size <= 0:
        return json({"status": "error", "error": "page or size must be greater than 0"})
    try:
        query = await db_model.operation_query()
        operation = await db_objects.get(query, name=user["current_operation"])
    except Exception as e:
        return json({"status": "error", "error": "failed to get current operation"})
    query = await db_model.callback_query()
    callbacks_query = query.where(Callback.operation == operation)
    count = await db_objects.count(callbacks_query)

    if page * size > count:
        page = ceil(count / size)
        if page == 0:
            page = 1
    cb = await db_objects.execute(
        callbacks_query.order_by(-Callback.id).paginate(page, size)
    )
    return json(
        {
            "status": "success",
            "callbacks": [c.to_json() for c in cb],
            "total_count": count,
            "page": page,
            "size": size,
        }
    )


# Get a single response
@mythic.route(mythic.config["API_BASE"] + "/callbacks/search", methods=["POST"])
@inject_user()
@scoped(
    ["auth:user", "auth:apitoken_user"], False
)  # user or user-level api token are ok
async def search_callbacks_with_pageinate(request, user):
    if user["auth"] not in ["access_token", "apitoken"]:
        abort(
            status_code=403,
            message="Cannot access via Cookies. Use CLI or access via JS in browser",
        )
    try:
        data = request.json
        if "search" not in data:
            return json({"status": "error", "error": "must supply a search term"})
        query = await db_model.operation_query()
        operation = await db_objects.get(query, name=user["current_operation"])
    except Exception as e:
        return json({"status": "error", "error": "Cannot find operation"})
    try:
        query = await db_model.callback_query()
        count = await db_objects.count(
            query.where(
                (Callback.operation == operation)
                & (Callback.host.regexp(data["search"]))
            )
        )

        if "page" not in data:
            cb = await db_objects.execute(
                query.where(
                    (Callback.operation == operation)
                    & (Callback.host.regexp(data["search"]))
                ).order_by(-Callback.id)
            )
            data["page"] = 1
            data["size"] = count
        else:
            if (
                "page" not in data
                or "size" not in data
                or int(data["size"]) <= 0
                or int(data["page"]) <= 0
            ):
                return json(
                    {
                        "status": "error",
                        "error": "size and page must be supplied and be greater than 0",
                    }
                )
            data["size"] = int(data["size"])
            data["page"] = int(data["page"])
            if data["page"] * data["size"] > count:
                data["page"] = ceil(count / data["size"])
                if data["page"] == 0:
                    data["page"] = 1
            cb = await db_objects.execute(
                query.where(
                    (Callback.operation == operation)
                    & (Callback.host.regexp(data["search"]))
                )
                .order_by(-Callback.id)
                .paginate(data["page"], data["size"])
            )
        return json(
            {
                "status": "success",
                "callbacks": [c.to_json() for c in cb],
                "total_count": count,
                "page": data["page"],
                "size": data["size"],
            }
        )
    except Exception as e:
        print(str(e))
        return json({"status": "error", "error": str(e)})


async def add_p2p_route(agent_message, callback, task):
    # { INPUT
    # "edges": [
    #    {
    #      "source": "uuid of callback",
    #      "destination": "uuid of adjoining callback",
    #      "direction": 1 or 2 or 3,
    #      "metadata": "{ optional metadata json string }",
    #       "action": "add" or "remove"
    #     }
    #   ]
    # }
    # { RESPONSE
    #   "status": "success" or "error"
    # }
    query = await db_model.callback_query()
    profile_query = await db_model.c2profile_query()
    # dijkstra is directed, so if we have a bidirectional connection (type 3) account for that as well
    for e in agent_message:
        if e["action"] == "add":
            try:
                profile = None
                source = await db_objects.get(query, agent_callback_id=e["source"])
                destination = await db_objects.get(
                    query, agent_callback_id=e["destination"]
                )
                if callback is None:
                    callback = source
                if source.operation.name not in current_graphs:
                    current_graphs[source.operation.name] = Graph()
                if (
                    "c2_profile" in e
                    and e["c2_profile"] is not None
                    and e["c2_profile"] != ""
                ):
                    profile = await db_objects.get(profile_query, name=e["c2_profile"])
                else:
                    # find an overlapping p2p profile in both agents, else error
                    callback_c2profile_query = await db_model.callbackc2profiles_query()
                    mutual_c2 = await db_objects.execute(
                        callback_c2profile_query.where(
                            (
                                (db_model.CallbackC2Profiles.callback == source)
                                | (db_model.CallbackC2Profiles.callback == destination)
                            )
                            & (db_model.C2Profile.is_p2p == True)
                        )
                    )
                    hist = []
                    for cc2 in mutual_c2:
                        if cc2.c2_profile.name not in hist:
                            hist.append(cc2.c2_profile.name)
                        else:
                            profile = cc2.c2_profile
                            break
                    if profile is None:
                        return {
                            "status": "error",
                            "error": "No matching p2p profiles",
                            "task_id": task.agent_task_id,
                        }
                # there can only be one source-destination-direction-metadata-c2_profile combination
                try:
                    edge = await db_objects.get(
                        db_model.CallbackGraphEdge,
                        source=source,
                        destination=destination,
                        direction=e["direction"],
                        metadata=e["metadata"],
                        operation=callback.operation,
                        c2_profile=profile,
                        end_timestamp=None,
                    )
                    return {
                        "status": "error",
                        "error": "edge already exists",
                        "task_id": task.agent_task_id,
                    }
                except Exception as error:
                    edge = await db_objects.create(
                        db_model.CallbackGraphEdge,
                        source=source,
                        destination=destination,
                        direction=e["direction"],
                        metadata=e["metadata"],
                        operation=callback.operation,
                        c2_profile=profile,
                        task_start=task,
                    )
                    await add_non_directed_graphs(edge)
                    await add_directed_graphs(edge)
            except Exception as d:
                print(d)
                if task is not None:
                    return {
                        "status": "error",
                        "error": str(d),
                        "task_id": task.agent_task_id,
                    }
                else:
                    return {"status": "error", "error": str(d), "task_id": None}
        if e["action"] == "remove":
            try:
                # find the edge its talking about
                # print(e)
                profile = None
                source = await db_objects.get(query, agent_callback_id=e["source"])
                destination = await db_objects.get(
                    query, agent_callback_id=e["destination"]
                )
                if callback is None:
                    callback = source
                if (
                    "c2_profile" in e
                    and e["c2_profile"] is not None
                    and e["c2_profile"] != ""
                ):
                    profile = await db_objects.get(profile_query, name=e["c2_profile"])
                else:
                    # find an overlapping p2p profile in both agents, else error
                    callback_c2profile_query = await db_model.callbackc2profiles_query()
                    mutual_c2 = await db_objects.execute(
                        callback_c2profile_query.where(
                            (
                                (db_model.CallbackC2Profiles.callback == source)
                                | (db_model.CallbackC2Profiles.callback == destination)
                            )
                            & (db_model.C2Profile.is_p2p == True)
                        )
                    )
                    hist = []
                    for cc2 in mutual_c2:
                        if cc2.c2_profile.name not in hist:
                            hist.append(cc2.c2_profile.name)
                        else:
                            profile = cc2.c2_profile
                            break
                    if profile is None:
                        return {
                            "status": "error",
                            "error": "No matching p2p profiles",
                            "task_id": task.agent_task_id,
                        }
                edge = await db_objects.get(
                    db_model.CallbackGraphEdge,
                    source=source,
                    destination=destination,
                    direction=e["direction"],
                    metadata=e["metadata"],
                    operation=callback.operation,
                    c2_profile=profile,
                    end_timestamp=None,
                )
                edge.end_timestamp = datetime.utcnow()
                edge.task_end = task
                await db_objects.update(edge)
                if source.operation.name not in current_graphs:
                    current_graphs[source.operation.name] = Graph()
                try:
                    await remove_non_directed_graphs(edge)
                    await remove_directed_graphs(edge)
                except Exception as e:
                    print("failed to remove edge from graph: " + str(e))
                    pass
            except Exception as d:
                print(d)
                if task is not None:
                    return {
                        "status": "error",
                        "error": str(d),
                        "task_id": task.agent_task_id,
                    }
                else:
                    return {"status": "error", "error": str(d), "task_id": task}
    if task is not None:
        return {"status": "success", "task_id": task.agent_task_id}
    else:
        return {"status": "success", "task_id": task}


async def remove_directed_graphs(edge):
    if edge.source.operation.name not in current_graphs:
        current_graphs[edge.source.operation.name] = Graph()
    if edge.direction == 1:
        current_graphs[edge.source.operation.name].remove_edge(
            edge.source, edge.destination
        )
    elif edge.direction == 2:
        current_graphs[edge.source.operation.name].remove_edge(
            edge.destination, edge.source
        )
    else:
        current_graphs[edge.source.operation.name].remove_edge(
            edge.source, edge.destination
        )
        current_graphs[edge.source.operation.name].remove_edge(
            edge.destination, edge.source
        )


async def add_directed_graphs(edge):
    if edge.source.operation.name not in current_graphs:
        current_graphs[edge.source.operation.name] = Graph()
    if edge.direction == 1:
        current_graphs[edge.source.operation.name].add_edge(
            edge.source, edge.destination, 1
        )
    elif edge.direction == 2:
        current_graphs[edge.source.operation.name].add_edge(
            edge.destination, edge.source, 1
        )
    else:
        current_graphs[edge.source.operation.name].add_edge(
            edge.source, edge.destination, 1
        )
        current_graphs[edge.source.operation.name].add_edge(
            edge.destination, edge.source, 1
        )


async def path_to_callback(callback):
    try:
        await update_non_directed_graphs(callback.operation)
        if current_non_directed_graphs[callback.operation.name].edge_count == 0:
            #print("no edges")
            return []  # graph for this operation has no edges
        try:
            path = find_path(
                current_non_directed_graphs[callback.operation.name], callback, "Mythic"
            )
        except NoPathError:
            #print("no path")
            return []
        return path.nodes
    except Exception as e:
        print("error in path_to_callback: " + str(e))
        return []
