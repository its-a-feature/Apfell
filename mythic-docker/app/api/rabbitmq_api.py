from app import db_objects
import datetime
import app.database_models.model as db_model
import aio_pika
import asyncio
import base64
import ujson as json
import sys
import os
from sanic.log import logger
from app.crypto import hash_SHA1, hash_MD5
from functools import partial
import traceback
import uuid
import app.crypto as crypt
from app.api.operation_api import send_all_operations_message
from app.api.siem_logger import log_to_siem


# Keep track of sending sync requests to containers so we don't go crazy
sync_tasks = {}


async def rabbit_c2_callback(message: aio_pika.IncomingMessage):
    with message.process():
        pieces = message.routing_key.split(".")
        # print(" [x] %r:%r" % (message.routing_key,message.body))
        if pieces[4] == "sync_classes":
            if pieces[5] == "":
                operator = None
            else:
                query = await db_model.operator_query()
                operator = await db_objects.get(
                    query, username=base64.b64decode(pieces[5]).decode()
                )
            from app.api.c2profiles_api import import_c2_profile_func

            try:
                status = await import_c2_profile_func(
                    json.loads(message.body.decode()), operator
                )
            except Exception as e:
                await send_all_operations_message("Failed Sync-ed database with {} C2 files: {}".format(
                    pieces[2], str(e)
                ), "warning")
                return
            if status["status"] == "success":
                sync_tasks.pop(pieces[2], None)
                await send_all_operations_message("Successfully Sync-ed database with {} C2 files".format(
                            pieces[2]
                        ), "info")
                # for a successful checkin, we need to find all non-wrapper payload types and get them to re-check in
                if status["new"]:
                    query = await db_model.payloadtype_query()
                    pts = await db_objects.execute(
                        query.where(db_model.PayloadType.wrapper == False)
                    )
                    sync_operator = "" if operator is None else operator.username
                    for pt in pts:
                        if pt.ptype not in sync_tasks:
                            sync_tasks[pt.ptype] = True
                            await send_pt_rabbitmq_message(
                                pt.ptype, "sync_classes", "", sync_operator
                            )
            else:
                sync_tasks.pop(pieces[2], None)
                await send_all_operations_message("Failed Sync-ed database with {} C2 files: {}".format(
                            pieces[2], status["error"]
                        ), "warning")
        if pieces[1] == "status":
            try:
                query = await db_model.c2profile_query()
                profile = await db_objects.get(query, name=pieces[2], deleted=False)
                if pieces[3] == "running" and not profile.running:
                    profile.running = True
                    await db_objects.update(profile)
                    await send_all_operations_message(message=f"C2 Profile {profile.name} has started", level="info")
                elif pieces[3] == "stopped" and profile.running:
                    profile.running = False
                    await db_objects.update(profile)
                    await send_all_operations_message(message=f"C2 Profile {profile.name} has stopped", level="warning")
                # otherwise we got a status that matches the current status, just move on
            except Exception as e:
                logger.exception(
                    "Exception in rabbit_c2_callback (status): {}, {}".format(
                        pieces, str(e)
                    )
                )
                # print("Exception in rabbit_c2_callback (status): {}, {}".format(pieces, str(e)))


async def rabbit_pt_callback(message: aio_pika.IncomingMessage):
    with message.process():
        pieces = message.routing_key.split(".")
        # print(" [x] %r:%r" % (
        #    message.routing_key,
        #    message.body.decode('utf-8')
        # ))
        if pieces[1] == "status":
            try:
                if pieces[3] == "create_payload_with_code":
                    # this means we should be getting back the finished payload or an error
                    query = await db_model.payload_query()
                    payload = await db_objects.get(query, uuid=pieces[4])
                    agent_message = json.loads(message.body.decode())
                    if agent_message["status"] == "success":
                        file = open(payload.file_id.path, "wb")
                        file.write(base64.b64decode(agent_message["payload"]))
                        file.close()
                        code = base64.b64decode(agent_message["payload"])
                        md5 = await hash_MD5(code)
                        sha1 = await hash_SHA1(code)
                        payload.file_id.md5 = md5
                        payload.file_id.sha1 = sha1
                        await db_objects.update(payload.file_id)
                        query = await db_model.buildparameterinstance_query()
                        current_instances = await db_objects.execute(
                            query.where(
                                db_model.BuildParameterInstance.payload == payload
                            )
                        )
                        for ci in current_instances:
                            if (
                                ci.build_parameter.name
                                in agent_message["build_parameter_instances"]
                            ):
                                ci.parameter = agent_message[
                                    "build_parameter_instances"
                                ][ci.build_parameter.name]
                                await db_objects.update(ci)
                                del agent_message["build_parameter_instances"][
                                    ci.build_parameter.name
                                ]
                        query = await db_model.buildparameter_query()
                        for k, v in agent_message["build_parameter_instances"].items():
                            # now create entries that were set to default in the build script that weren't supplied by the user
                            try:
                                bp = await db_objects.get(
                                    query, name=k, payload_type=payload.payload_type
                                )
                                await db_objects.create(
                                    db_model.BuildParameterInstance,
                                    parameter=v,
                                    payload=payload,
                                    build_parameter=bp,
                                )
                            except Exception as e:
                                agent_message[
                                    "message"
                                ] += "Failed to find build parameter for name {}".format(
                                    k
                                )
                    payload.build_phase = agent_message["status"]
                    payload.build_message = agent_message["message"]
                    await db_objects.update(payload)
                    await log_to_siem(payload.to_json(), mythic_object="payload_new")
                elif pieces[3] == "command_transform":
                    query = await db_model.task_query()
                    task = await db_objects.get(query, id=pieces[5])
                    if pieces[4] == "error":
                        # create a response that there was an error and set task to processed
                        task.status = "error"
                        task.completed = True
                        task.timestamp = datetime.datetime.utcnow()
                        task.status_timestamp_processed = task.timestamp
                        await db_objects.create(
                            db_model.Response,
                            task=task,
                            response=message.body.decode("utf-8"),
                        )
                        await db_objects.update(task)
                    else:
                        task.params = message.body
                        task.timestamp = datetime.datetime.utcnow()
                        if pieces[4] == "success":
                            task.status = "submitted"
                        elif pieces[4] == "completed":
                            task.status = "processed"
                            task.completed = True
                        else:
                            task.status = pieces[4]
                        task.status_timestamp_submitted = task.timestamp
                        await db_objects.update(task)
                        await log_to_siem(task.to_json(), mythic_object="task_new")
                        await add_command_attack_to_task(task, task.command)
                elif pieces[3] == "sync_classes":
                    if pieces[5] == "" or pieces[5] is None:
                        # this was an auto sync from starting a container
                        operator = None
                    else:
                        operator_query = await db_model.operator_query()
                        operator = await db_objects.get(
                            operator_query,
                            username=base64.b64decode(pieces[5]).decode(),
                        )
                    sync_tasks.pop(pieces[2], None)
                    if pieces[4] == "success":
                        from app.api.payloadtype_api import import_payload_type_func
                        try:
                            status = await import_payload_type_func(
                                json.loads(message.body.decode()), operator
                            )
                            if status["status"] == "success":
                                await send_all_operations_message("Successfully Sync-ed database with {} payload files".format(
                                            pieces[2]
                                        ), "info")
                                if status["wrapper"] and status["new"]:
                                    query = await db_model.payloadtype_query()
                                    pts = await db_objects.execute(
                                        query.where(
                                            db_model.PayloadType.wrapper == False
                                        )
                                    )
                                    sync_operator = (
                                        "" if operator is None else operator.username
                                    )
                                    for pt in pts:
                                        if pt.ptype not in sync_tasks:
                                            sync_tasks[pt.ptype] = True
                                            print("got sync from {}, sending sync to {}".format(pieces[2], pt.ptype))
                                            await send_pt_rabbitmq_message(
                                                pt.ptype, "sync_classes", "", sync_operator
                                            )
                            else:
                                await send_all_operations_message("Failed Sync-ed database with {} payload files: {}".format(
                                            pieces[2], status["error"]
                                        ), "warning")
                        except Exception as i:
                            await send_all_operations_message("Failed Sync-ed database with {} payload files: {}".format(
                                        pieces[2], status["error"]
                                    ), "warning")
                    else:
                        await send_all_operations_message("Failed getting information for payload {} with error: {}".format(
                                    pieces[2], message.body.decode()
                                ), "warning")
            except Exception as e:
                logger.exception("Exception in rabbit_pt_callback: " + str(e))
                print(str(sys.exc_info()[-1].tb_lineno) + " " + str(e))
                # print("Exception in rabbit_pt_callback: " + str(e))


async def rabbit_pt_rpc_callback(
    exchange: aio_pika.Exchange, message: aio_pika.IncomingMessage
):
    with message.process():
        request = json.loads(message.body.decode())
        if "task_id" not in request:
            response = json.dumps(
                {"status": "error", "error": "Missing task_id"}
            ).encode()
        elif "action" in request:
            if request["action"] == "register_file":
                response = await register_file(request)
            elif request["action"] == "get_file_by_name":
                response = await get_file_by_name(request)
            elif request["action"] == "get_payload_by_uuid":
                response = await get_payload_by_uuid(request)
            elif request["action"] == "build_payload_from_template":
                response = await build_payload_from_template(request)
            elif request["action"] == "control_socks":
                response = await control_socks(request)
            elif request["action"] == "encrypt_bytes":
                response = await encrypt_bytes(request)
            elif request["action"] == "decrypt_bytes":
                response = await decrypt_bytes(request)
            elif request["action"] == "user_output":
                response = await user_output(request)
            elif request["action"] == "update_callback":
                response = await task_update_callback(request)
            elif request["action"] == "register_artifact":
                response = await register_artifact(request)
            elif request["action"] == "build_payload_from_parameters":
                response = await build_payload_from_parameters(request)
            elif request["action"] == "register_payload_on_host":
                response = await register_payload_on_host(request)
            elif request["action"] == "control_rportfwd":
                response = await control_rportfwd(request)
            else:
                response = {"status": "error", "error": "unknown action"}
            response = json.dumps(response).encode()
        else:
            response = json.dumps(
                {"status": "error", "error": "Missing action"}
            ).encode()
        try:
            await exchange.publish(
                aio_pika.Message(body=response, correlation_id=message.correlation_id),
                routing_key=message.reply_to,
            )
        except Exception as e:
            error = (
                "Exception trying to send message back to container for rpc! " + str(e)
            )
            error += "\nResponse: {}\nCorrelation_id: {}\n RoutingKey: {}".format(
                str(response), message.correlation_id, message.reply_to
            )
            task_query = await db_model.task_query()
            task = await db_objects.get(task_query, id=request["task_id"])
            task.status = "error"
            task.completed = True
            await db_objects.update(task)
            await db_objects.create(
                db_model.Response, task=task, response=error.encode("unicode-escape")
            )


async def register_file(request):
    # {
    # "action": "register_file",
    # "file": base64.b64encode(file).decode(),
    # "task_id": self.task_id
    # "delete_after_fetch": True,
    # "saved_file_name": str(uuid.uuid4()),
    # "remote_path": "",
    # "is_screenshot": False,
    # "is_download": False,
    # }
    try:
        task_query = await db_model.task_query()
        task = await db_objects.get(task_query, id=request["task_id"])
        filename = (
            request["saved_file_name"]
            if "saved_file_name" in request
            else str(uuid.uuid4())
        )
        path = "./app/files/{}".format(str(uuid.uuid4()))
        code_file = open(path, "wb")
        code = base64.b64decode(request["file"])
        code_file.write(code)
        code_file.close()
        size = os.stat(path).st_size
        md5 = await hash_MD5(code)
        sha1 = await hash_SHA1(code)
        new_file_meta = await db_objects.create(
            db_model.FileMeta,
            total_chunks=1,
            chunks_received=1,
            chunk_size=size,
            complete=True,
            path=str(path),
            operation=task.callback.operation,
            operator=task.operator,
            full_remote_path=request["remote_path"],
            md5=md5,
            sha1=sha1,
            task=task,
            delete_after_fetch=request["delete_after_fetch"],
            filename=filename,
            is_screenshot=request["is_screenshot"],
            is_download_from_agent=request["is_download"],
        )
        await log_to_siem(new_file_meta.to_json(), mythic_object="file_upload")
        return {"status": "success", "response": new_file_meta.to_json()}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def get_file_by_name(request):
    try:
        task_query = await db_model.task_query()
        task = await db_objects.get(task_query, id=request["task_id"])
        file_query = await db_model.filemeta_query()
        files = await db_objects.execute(
            file_query.where(
                (db_model.FileMeta.deleted == False)
                & (db_model.FileMeta.filename == request["filename"])
                & (db_model.FileMeta.operation == task.callback.operation)
            ).order_by(db_model.FileMeta.timestamp)
        )
        file = None
        for f in files:
            file = f
        if file is None:
            return {"status": "error", "error": "File not found"}
        else:
            file_json = file.to_json()
            if os.path.exists(file.path):
                file_json["contents"] = base64.b64encode(
                    open(file.path, "rb").read()
                ).decode()
            return {"status": "success", "response": file_json}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def get_payload_by_uuid(request):
    try:
        payload_query = await db_model.payload_query()
        payload = await db_objects.get(payload_query, uuid=request["uuid"])
        payload_json = payload.to_json()
        payload_json["contents"] = ""
        if os.path.exists(payload.file_id.path):
            payload_json["contents"] = base64.b64encode(
                open(payload.file_id.path, "rb").read()
            ).decode()
        from app.api.task_api import add_all_payload_info

        payload_info = await add_all_payload_info(payload)
        payload_json["commands"] = payload_info["commands"]
        payload_json["c2info"] = payload_info["c2info"]
        payload_json["build_parameters"] = payload_info["build_parameters"]
        return {"status": "success", "response": payload_json}
    except Exception as e:
        print(str(traceback.format_exc()))
        return {"status": "error", "error": "Payload not found"}


async def build_payload_from_template(request):
    # check to make sure we have the right parameters (host, template)
    from app.api.payloads_api import register_new_payload_func, write_payload
    from app.api.c2profiles_api import generate_random_format_string

    try:
        task_query = await db_model.task_query()
        task = await db_objects.get(task_query, id=request["task_id"])
        # default to the template of the current payload unless otherwise specified
        template = task.callback.registered_payload
        host = task.callback.host.upper()
        task.status = "building..."
        await db_objects.update(task)
        if "uuid" in request and request["uuid"] != "" and request["uuid"] is not None:
            # pull that associated payload
            query = await db_model.payload_query()
            template = await db_objects.get(query, uuid=request["uuid"])
        if (
            "destination_host" in request
            and request["destination_host"] != ""
            and request["destination_host"] is not None
            and request["destination_host"] not in ["localhost", "127.0.0.1", "::1"]
        ):
            host = request["destination_host"].upper()
        # using that payload, generate the following build-tasking data
        data = {
            "payload_type": template.payload_type.ptype,
            "c2_profiles": [],
            "commands": [],
            "tag": "Autogenerated from task {} on callback {}".format(
                str(task.id), str(task.callback.id)
            ),
            "wrapper": template.payload_type.wrapper,
        }
        if data["wrapper"]:
            if "wrapped_payload" not in request or request["wrapped_payload"] is None:
                data["wrapped_payload"] = template.wrapped_payload.uuid
        if "description" in request:
            if request["description"] is not None and request["description"] != "":
                data["tag"] = request["description"]
        query = await db_model.payloadcommand_query()
        payloadcommands = await db_objects.execute(
            query.where(db_model.PayloadCommand.payload == template)
        )
        data["commands"] = [c.command.cmd for c in payloadcommands]
        query = await db_model.buildparameterinstance_query()
        create_transforms = await db_objects.execute(
            query.where(db_model.BuildParameterInstance.payload == template)
        )
        data["build_parameters"] = [t.to_json() for t in create_transforms]
        for t in data["build_parameters"]:
            t["name"] = t["build_parameter"]["name"]
            t["value"] = t["parameter"]
        c2_profiles_data = []
        query = await db_model.payloadc2profiles_query()
        c2profiles = await db_objects.execute(
            query.where(db_model.PayloadC2Profiles.payload == template)
        )
        for c2p in c2profiles:
            query = await db_model.c2profileparametersinstance_query()
            c2_profile_params = await db_objects.execute(
                query.where(
                    (db_model.C2ProfileParametersInstance.payload == template)
                    & (
                        db_model.C2ProfileParametersInstance.c2_profile
                        == c2p.c2_profile
                    )
                )
            )
            params = {}
            for p in c2_profile_params:
                if p.c2_profile_parameters.randomize:
                    params[
                        p.c2_profile_parameters.name
                    ] = await generate_random_format_string(
                        p.c2_profile_parameters.format_string
                    )
                else:
                    params[p.c2_profile_parameters.name] = p.value
            c2_profiles_data.append(
                {"c2_profile": c2p.c2_profile.name, "c2_profile_parameters": params}
            )
        data["c2_profiles"] = c2_profiles_data
        data["filename"] = "Task" + str(task.id) + "Copy_" + template.file_id.filename
        # print(data)
        # upon successfully starting the build process, set pcallback and task
        #   when it's successfully written, it will get a file_id with it
        rsp = await register_new_payload_func(
            data,
            {
                "current_operation": task.callback.operation.name,
                "username": task.operator.username,
            },
        )
        return await handle_automated_payload_creation_response(task, rsp, data, host)
    except Exception as e:
        print(str(sys.exc_info()[-1].tb_lineno) + " " + str(traceback.format_exc()))
        return {
            "status": "error",
            "error": "Failed to build payload: " + str(traceback.format_exc()),
        }


async def build_payload_from_parameters(request):
    try:
        from app.api.payloads_api import register_new_payload_func
        task_query = await db_model.task_query()
        task = await db_objects.get(task_query, id=request["task_id"])
        host = task.callback.host.upper()
        task.status = "building..."
        await db_objects.update(task)
        if (
            "destination_host" in request
            and request["destination_host"] != ""
            and request["destination_host"] is not None
            and request["destination_host"] not in ["localhost", "127.0.0.1", "::1"]
        ):
            host = request["destination_host"].upper()
        if "tag" not in request or request["tag"] == "":
            request["tag"] = "Autogenerated from task {} on callback {}".format(
                str(task.id), str(task.callback.id))
        if "filename" not in request or request["filename"] == "":
            request["filename"] = "Task" + str(task.id) + "Payload"
        rsp = await register_new_payload_func(
            request,
            {
                "current_operation": task.callback.operation.name,
                "username": task.operator.username,
            },
        )
        return await handle_automated_payload_creation_response(task, rsp, request, host)
    except Exception as e:
        return {
            "status": "error",
            "error": "Failed to build payload: " + str(traceback.format_exc()),
        }


async def handle_automated_payload_creation_response(task, rsp, data, host):
    from app.api.payloads_api import write_payload

    if rsp["status"] == "success":
        query = await db_model.payload_query()
        payload = await db_objects.get(query, uuid=rsp["uuid"])
        payload.task = task
        payload.pcallback = task.callback
        payload.auto_generated = True
        payload.callback_alert = False
        payload.file_id.delete_after_fetch = True
        await db_objects.update(payload.file_id)
        await db_objects.update(payload)
        # send a message back to the container to build a new payload
        create_rsp = await write_payload(
            payload.uuid,
            {
                "current_operation": task.callback.operation.name,
                "username": task.operator.username,
            },
            data,
        )
        if create_rsp["status"] != "success":
            payload.deleted = True
            await db_objects.update(payload)
            task.status = "error"
            await db_objects.create(
                db_model.Response,
                task=task,
                response="Exception when building payload: {}".format(
                    create_rsp["error"]
                ),
            )
            return {
                "status": "error",
                "error": "Failed to send build message to container: "
                         + create_rsp["error"],
            }
        else:
            task.status = "building..."
            task.timestamp = datetime.datetime.utcnow()
            await db_objects.update(task)
            await db_objects.create(
                db_model.PayloadOnHost,
                host=host.upper(),
                payload=payload,
                operation=payload.operation,
                task=task,
            )
        from app.api.task_api import add_all_payload_info

        payload_info = await add_all_payload_info(payload)
        payload_info = {**payload_info, **payload.to_json()}
        return {"status": "success", "response": payload_info}
    else:
        await db_objects.create(
            db_model.Response,
            task=task,
            response="Exception when registering payload: {}".format(rsp["error"]),
        )
        return {
            "status": "error",
            "error": "Failed to register new payload: " + rsp["error"],
        }


async def control_socks(request):
    task_query = await db_model.task_query()
    task = await db_objects.get(task_query, id=request["task_id"])
    if "start" in request:
        from app.api.callback_api import start_socks

        resp = await start_socks(request["port"], task.callback, task)
        return resp
    if "stop" in request:
        from app.api.callback_api import stop_socks

        resp = await stop_socks(task.callback, task.operator)
        return resp
    return {"status": "error", "error": "unknown socks tasking"}


async def control_rportfwd(request):
    task_query = await db_model.task_query()
    task = await db_objects.get(task_query, id=request["task_id"])
    if "start" in request:
        from app.api.callback_api import start_rportfwd
        resp = await start_rportfwd(request["port"],request["rport"],request["rip"], task.callback, task)
        return resp
    if "stop" in request:
        from app.api.callback_api import stop_rportfwd
        resp = await stop_rportfwd(request["port"], task.callback, task)
        return resp
    if "flush" in request:
        from app.api.callback_api import flush_rportfwd

        resp = await flush_rportfwd(task.callback, task)
        return resp
    return {"status": "error", "error": "unknown rportfwd tasking"}

async def encrypt(callback_uuid: str, data: bytes, with_uuid: bool):
    from app.api.callback_api import get_encryption_data
    enc_key = await get_encryption_data(callback_uuid)
    message = await crypt.encrypt_bytes_normalized(data, enc_key, callback_uuid, with_uuid)
    if message == "":
        callback_query = await db_model.callback_query()
        callback = await db_objects.get(callback_query, agent_callback_id=callback_uuid)
        await db_objects.create(
            db_model.OperationEventLog,
            level="warning",
            operation=callback.operation,
            message="Payload or C2 profile tried to have Mythic encrypt a message of type: {}, but Mythic doesn't know that type".format(
                enc_key["type"]),
        )
    return message


async def encrypt_bytes(request):
    # {
    # "action": "encrypt_bytes",
    # "data": base64 of bytes to encrypt,
    # "task_id": self.task_id
    # "with_uuid": include the UUID or not
    # }
    try:
        task_query = await db_model.task_query()
        task = await db_objects.get(task_query, id=request["task_id"])
        message = await encrypt(task.callback.agent_callback_id, base64.b64decode(request["data"]), request["with_uuid"])
        return {"status": "success", "response": {"data": message}}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def encrypt_bytes_c2_rpc(request):
    # {
    # "action": "encrypt_bytes",
    # "data": base64 of bytes to encrypt,
    # "uuid": callback uuid
    # "with_uuid": bool
    # }
    try:
        message = await encrypt(request["uuid"], base64.b64decode(request["data"]), request["with_uuid"])
        return {"status": "success", "response": message}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def decrypt(callback_uuid: str, data: bytes, with_uuid: bool):
    from app.api.callback_api import get_encryption_data
    dec_key = await get_encryption_data(callback_uuid)
    dec_message = await crypt.decrypt_message(data, dec_key, with_uuid, False)
    if dec_message == b'' or dec_message == {}:
        callback_query = await db_model.callback_query()
        callback = await db_objects.get(callback_query, agent_callback_id=callback_uuid)
        await db_objects.create(
            db_model.OperationEventLog,
            level="warning",
            operation=callback.operation,
            message="Payload or C2 profile tried to have Mythic decrypt a message of type: {}, but Mythic doesn't know that type".format(
                dec_key["type"]),
        )
    return base64.b64encode(dec_message).decode()


async def decrypt_bytes(request):
    # {
    # "action": "decrypt_bytes",
    # "data": base64 of bytes to decrypt,
    # "task_id": self.task_id
    # "with_uuid": does the message have a UUID in it or not
    # }
    try:
        task_query = await db_model.task_query()
        task = await db_objects.get(task_query, id=request["task_id"])
        dec_message = await decrypt(task.callback.agent_callback_id, base64.b64decode(request["data"]), request["with_uuid"])
        return {
            "status": "success",
            "response": {"data": dec_message},
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def decrypt_bytes_c2_rpc(request):
    # {
    # "action": "decrypt_bytes",
    # "data": base64 of bytes to decrypt,
    # "uuid": callback uuid
    # "with_uuid": does the message have a UUID in it or not
    # }
    try:
        dec_message = await decrypt(request["uuid"], base64.b64decode(request["data"]), request["with_uuid"])
        return {
            "status": "success",
            "response": dec_message,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def user_output(request):
    try:
        task_query = await db_model.task_query()
        task = await db_objects.get(task_query, id=request["task_id"])
        resp = await db_objects.create(
            db_model.Response,
            task=task,
            response=request["user_output"].encode("unicode-escape"),
        )
        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def task_update_callback(request):
    try:
        task_query = await db_model.task_query()
        task = await db_objects.get(task_query, id=request["task_id"])
        from app.api.callback_api import update_callback

        status = await update_callback(
            request["callback_info"], task.callback.agent_callback_id
        )
        return status
    except Exception as e:
        print("error in task_update:" + str(e))
        return {"status": "error", "error": str(e)}


async def register_artifact(request):
    # {"action": "register_artifact",
    # "task_id": self.task_id,
    # "host": host, (could be None)
    # "artifact_instance": artifact_instance,
    # "artifact": artifact_type
    # })
    try:
        task_query = await db_model.task_query()
        task = await db_objects.get(task_query, id=request["task_id"])
    except Exception as e:
        return {"status": "error", "error": "failed to find task"}
    try:

        # first try to look for the artifact type, if it doesn't exist, create it
        query = await db_model.artifact_query()
        artifact = await db_objects.get(query, name=request["artifact"].encode())
    except Exception as e:
        artifact = await db_objects.create(db_model.Artifact, name=request["artifact"].encode())
    try:
        if "host" not in request or request["host"] is None or request["host"] == "":
            request["host"] = task.callback.host
        art = await db_objects.create(
            db_model.TaskArtifact,
            task=task,
            artifact_instance=request["artifact_instance"].encode(),
            artifact=artifact,
            host=request["host"].upper(),
            operation=task.callback.operation,
        )
        await log_to_siem(art.to_json(), mythic_object="artifact_new")
        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "error": "failed to create task artifact: " + str(e)}


async def register_payload_on_host(request):
    # {"action": "register_payload_on_host",
    # "task_id": self.task_id,
    # "host": host,
    # "uuid": payload uuid
    # })
    try:
        task_query = await db_model.task_query()
        task = await db_objects.get(task_query, id=request["task_id"])
    except Exception as e:
        return {"status": "error", "error": "failed to find task"}
    try:
        payloadquery = await db_model.payload_query()
        payload = await db_objects.get(payloadquery, uuid=request["uuid"], operation=task.operation)
        payload_on_host = await db_objects.create(db_model.PayloadOnHost, payload=payload,
                                                  host=request["host"].upper().encode(), operation=task.operation, task=task)
        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "error": "Failed to find payload"}


async def rabbit_c2_rpc_callback(
    exchange: aio_pika.Exchange, message: aio_pika.IncomingMessage
):
    with message.process():
        #print(message)
        request = json.loads(message.body.decode())
        if "action" in request:
            if request["action"] == "get_tasking":
                response = await get_tasking(request)
            elif request["action"] == "add_route":
                response = await add_route(request)
            elif request["action"] == "remove_route":
                response = await remove_route(request)
            elif request["action"] == "get_callback_info":
                response = await get_callback_info(request)
            elif request["action"] == "update_callback_info":
                response = await update_callback_info(request)
            elif request["action"] == "add_event_message":
                response = await add_event_message(request)
            elif request["action"] == "get_encryption_data":
                response = await get_encryption_data(request)
            elif request["action"] == "encrypt_bytes":
                response = await encrypt_bytes_c2_rpc(request)
            elif request["action"] == "decrypt_bytes":
                response = await decrypt_bytes_c2_rpc(request)
            else:
                response = {"status": "error", "error": "unknown action"}
            response = json.dumps(response).encode()
        else:
            response = json.dumps(
                {"status": "error", "error": "Missing action"}
            ).encode()
        try:
            await exchange.publish(
                aio_pika.Message(body=response, correlation_id=message.correlation_id),
                routing_key=message.reply_to,
            )
        except Exception as e:
            error = (
                "Exception trying to send message back to container for rpc! " + str(e)
            )
            error += "\nResponse: {}\nCorrelation_id: {}\n RoutingKey: {}".format(
                str(response), message.correlation_id, message.reply_to
            )
            operation_query = await db_model.operation_query()
            operations = await db_objects.execute(
                operation_query.where(db_model.Operation.complete == False)
            )
            for o in operations:
                await db_objects.create(
                    db_model.OperationEventLog,
                    level="warning",
                    operation=o,
                    message="Failed to process C2 RPC: {}".format(str(e)),
                )


async def get_tasking(request):
    try:
        query = await db_model.callback_query()
        callback = await db_objects.get(query, agent_callback_id=request["uuid"])
        decrypted = {"action": "get_tasking", "tasking_size": request["tasking_size"]}
        from app.api.callback_api import get_agent_tasks, get_routable_messages

        response_data = await get_agent_tasks(decrypted, callback)
        delegates = await get_routable_messages(callback)
        if delegates is not None:
            response_data["delegates"] = delegates
        from app.crypto import encrypt_AES256
        from app.api.callback_api import get_encryption_data

        enc_key = await get_encryption_data(callback.agent_callback_id)
        if enc_key["type"] is not None:
            if enc_key["type"] == "AES256":
                enc_message = await encrypt_AES256(
                    json.dumps(response_data).encode(),
                    base64.b64decode(callback.encryption_key),
                )
            else:
                enc_message = json.dumps(response_data).encode()
            enc_message = base64.b64encode(
                callback.agent_callback_id.encode() + enc_message
            ).decode()
        else:
            enc_message = base64.b64encode(
                (callback.agent_callback_id + json.dumps(response_data)).encode()
            ).decode()
        return {"status": "success", "response": {"encrypted": enc_message, "raw": response_data}}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def get_callback_info(request):
    try:
        query = await db_model.callback_query()
        callback = await db_objects.get(query, agent_callback_id=request["uuid"])
        cjson = callback.to_json()
        cjson["encryption_type"] = callback.encryption_type
        cjson["encryption_key"] = callback.encryption_key
        cjson["decryption_key"] = callback.decryption_key
        return {"status": "success", "response": cjson}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def get_encryption_data(request):
    try:
        # given a UUID and profile name, get all of the saved parameter values for that UUID
        #   could be payload or callback though, so check both
        profile_query = await db_model.c2profile_query()
        profile = await db_objects.get(profile_query, name=request["c2_profile"])
        try:
            callback_query = await db_model.callback_query()
            callback = await db_objects.get(
                callback_query, agent_callback_id=request["uuid"]
            )
            # if it's a callback, get the current parameters
            cjson = {"uuid_type": "callback"}
            cjson["encryption_type"] = callback.encryption_type
            cjson["encryption_key"] = callback.encryption_key
            cjson["decryption_key"] = callback.decryption_key
            return {"status": "success", "response": cjson}
        except Exception as c:
            # that's ok, might just be a payload rather than a callback
            payload_query = await db_model.payload_query()
            payload = await db_objects.get(payload_query, uuid=request["uuid"])
            cjson = {"uuid_type": "payload"}
            for p in payload.payload_profile_parameters:
                if p.c2_profile == profile:
                    cjson[p.c2_profile_parameters.name] = p.value
            return {"status": "success", "response": cjson}
            # if we get another exception trying to get it as a payload, fall through to error
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def update_callback_info(request):
    try:
        from app.api.callback_api import update_callback

        status = await update_callback(request["data"], request["uuid"])
        return status
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def add_event_message(request):
    try:
        operation_query = await db_model.operation_query()
        operations = await db_objects.execute(
            operation_query.where(db_model.Operation.complete == False)
        )
        for o in operations:
            msg = await db_objects.create(
                db_model.OperationEventLog,
                level=request["level"],
                operation=o,
                message=request["message"],
            )
            await log_to_siem(msg.to_json(), mythic_object="eventlog_new")
        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def add_route(request):
    # {"action": "add_route",
    # "source": source_uuid,
    # "destination": destination_uuid,
    # "direction": direction,
    # "metadata": metadata
    # }
    from app.api.callback_api import add_p2p_route

    request["action"] = "add"
    rsp = await add_p2p_route(request, None, None)
    return rsp


async def remove_route(request):
    # {"action": "remove_route",
    # "source": source_uuid,
    # "destination": destination_uuid,
    # "direction": direction,
    # "metadata": metadata
    # }
    from app.api.callback_api import add_p2p_route

    request["action"] = "remove"
    rsp = await add_p2p_route(request, None, None)
    return rsp


async def add_command_attack_to_task(task, command):
    try:
        query = await db_model.attackcommand_query()
        attack_mappings = await db_objects.execute(
            query.where(db_model.ATTACKCommand.command == command)
        )
        for attack in attack_mappings:
            try:
                query = await db_model.attacktask_query()
                # try to get the query, if it doens't exist, then create it in the exception
                await db_objects.get(query, task=task, attack=attack.attack)
            except Exception as e:
                attack = await db_objects.create(
                    db_model.ATTACKTask, task=task, attack=attack.attack
                )
                await log_to_siem(attack.to_json(), mythic_object="task_mitre_attack")
    except Exception as e:
        #logger.exception(str(sys.exc_info()[-1].tb_lineno) + " " + str(e))
        print(str(sys.exc_info()[-1].tb_lineno) + " " + str(e))
        raise e


async def rabbit_heartbeat_callback(message: aio_pika.IncomingMessage):
    with message.process():
        pieces = message.routing_key.split(".")
        # print(" [x] %r:%r" % (
        #    message.routing_key,
        #    message.body
        # ))
        try:
            if pieces[0] == "c2":
                query = await db_model.c2profile_query()
                try:
                    profile = await db_objects.get(query, name=pieces[2], deleted=False)
                except Exception as e:
                    if pieces[2] not in sync_tasks:
                        sync_tasks[pieces[2]] = True
                        await send_all_operations_message(message=f"sending container sync message to {pieces[2]}",
                                                          level="info")
                        await send_c2_rabbitmq_message(pieces[2], "sync_classes", "", "")
                    return
                if (
                    profile.last_heartbeat
                    < datetime.datetime.utcnow() + datetime.timedelta(seconds=-30)
                    or not profile.container_running
                ):
                    if profile.running:
                        await send_all_operations_message(message=f"{profile.name}'s internal server stopped",
                                                          level="warning")
                        profile.running = False  # container just started, clearly the inner service isn't running
                    # print("setting running to false")
                profile.container_running = True
                profile.last_heartbeat = datetime.datetime.utcnow()
                await db_objects.update(profile)
            elif pieces[0] == "pt":
                ptquery = await db_model.payloadtype_query()
                try:
                    payload_type = await db_objects.get(
                        ptquery, ptype=pieces[2], deleted=False
                    )
                    payload_type.container_running = True
                    payload_type.last_heartbeat = datetime.datetime.utcnow()
                    await db_objects.update(payload_type)
                except Exception as e:
                    if pieces[2] not in sync_tasks:
                        # don't know the ptype, but haven't sent a sync request either, wait for an auto sync
                        sync_tasks[pieces[2]] = True
                    else:
                        # don't know the ptype and haven't seen an auto sync, force a sync
                        sync_tasks.pop(pieces[2], None)
                        await send_all_operations_message(message=f"sending container sync message to {pieces[2]}",
                                                          level="info")
                        await send_pt_rabbitmq_message(pieces[2], "sync_classes", "", "")
        except Exception as e:
            logger.exception(
                "Exception in rabbit_heartbeat_callback: {}, {}".format(pieces, str(e))
            )
            # print("Exception in rabbit_heartbeat_callback: {}, {}".format(pieces, str(e)))


# just listen for c2 heartbeats and update the database as necessary
async def start_listening():
    logger.debug("starting to consume rabbitmq messages")
    task = None
    task2 = None
    task3 = None
    task4 = None
    task5 = None
    tasks = [task, task2, task3, task4, task5]
    try:
        task = asyncio.ensure_future(connect_and_consume_c2())
        task2 = asyncio.ensure_future(connect_and_consume_heartbeats())
        task3 = asyncio.ensure_future(connect_and_consume_pt())
        task4 = asyncio.ensure_future(connect_and_consume_rpc())
        task5 = asyncio.ensure_future(connect_and_consume_c2_rpc())
        await asyncio.wait_for([task, task2, task3, task4, task5], None)
    except Exception as e:
        for t in tasks:
            if t is not None:
                task.cancel()
        await asyncio.sleep(3)


async def connect_and_consume_c2():
    connection = None
    while connection is None:
        try:
            connection = await aio_pika.connect_robust(
                host="127.0.0.1",
                login="mythic_user",
                password="mythic_password",
                virtualhost="mythic_vhost",
            )
            channel = await connection.channel()
            # declare our exchange
            await channel.declare_exchange(
                "mythic_traffic", aio_pika.ExchangeType.TOPIC
            )
            # get a random queue that only the mythic server will use to listen on to catch all heartbeats
            queue = await channel.declare_queue("", exclusive=True)
            # bind the queue to the exchange so we can actually catch messages
            await queue.bind(exchange="mythic_traffic", routing_key="c2.status.#")

            await channel.set_qos(prefetch_count=50)
            logger.info(" [*] Waiting for messages in connect_and_consume_c2.")
            try:
                task = queue.consume(rabbit_c2_callback)
                result = await asyncio.wait_for(task, None)
            except Exception as e:
                logger.exception(
                    "Exception in connect_and_consume .consume: {}".format(str(e))
                )
                # print("Exception in connect_and_consume .consume: {}".format(str(e)))
        except (ConnectionError, ConnectionRefusedError) as c:
            logger.error("Connection to rabbitmq failed, trying again...")
        except Exception as e:
            logger.exception(
                "Exception in connect_and_consume connect: {}".format(str(e))
            )
            # print("Exception in connect_and_consume connect: {}".format(str(e)))
        await asyncio.sleep(2)


async def connect_and_consume_pt():
    connection = None
    while connection is None:
        try:
            connection = await aio_pika.connect_robust(
                host="127.0.0.1",
                login="mythic_user",
                password="mythic_password",
                virtualhost="mythic_vhost",
            )
            channel = await connection.channel()
            # declare our exchange
            await channel.declare_exchange(
                "mythic_traffic", aio_pika.ExchangeType.TOPIC
            )
            # get a random queue that only the mythic server will use to listen on to catch all heartbeats
            queue = await channel.declare_queue("", exclusive=True)
            # bind the queue to the exchange so we can actually catch messages
            await queue.bind(exchange="mythic_traffic", routing_key="pt.status.#")
            await channel.set_qos(prefetch_count=50)
            logger.info(" [*] Waiting for messages in connect_and_consume_pt.")
            try:
                task = queue.consume(rabbit_pt_callback)
                result = await asyncio.wait_for(task, None)
            except Exception as r:
                logger.exception(
                    "Exception in connect_and_consume .consume: {}".format(str(r))
                )
                # print("Exception in connect_and_consume .consume: {}".format(str(e)))
        except (ConnectionError, ConnectionRefusedError) as c:
            logger.error("Connection to rabbitmq failed, trying again...")
        except Exception as e:
            logger.exception(
                "Exception in connect_and_consume connect: {}".format(str(e))
            )
            # print("Exception in connect_and_consume connect: {}".format(str(e)))
        await asyncio.sleep(2)


async def connect_and_consume_rpc():
    connection = None
    while connection is None:
        try:
            connection = await aio_pika.connect_robust(
                host="127.0.0.1",
                login="mythic_user",
                password="mythic_password",
                virtualhost="mythic_vhost",
            )
            channel = await connection.channel()
            # get a random queue that only the mythic server will use to listen on to catch all heartbeats
            queue = await channel.declare_queue("rpc_queue")
            await channel.set_qos(prefetch_count=50)
            logger.info(" [*] Waiting for messages in connect_and_consume_rpc.")
            try:
                task = queue.consume(
                    partial(rabbit_pt_rpc_callback, channel.default_exchange)
                )
                result = await asyncio.wait_for(task, None)
            except Exception as e:
                logger.exception(
                    "Exception in connect_and_consume_rpc .consume: {}".format(str(e))
                )
                # print("Exception in connect_and_consume .consume: {}".format(str(e)))
        except (ConnectionError, ConnectionRefusedError) as c:
            logger.error("Connection to rabbitmq failed, trying again...")
        except Exception as e:
            logger.exception(
                "Exception in connect_and_consume_rpc connect: {}".format(str(e))
            )
            # print("Exception in connect_and_consume connect: {}".format(str(e)))
        await asyncio.sleep(2)


async def connect_and_consume_c2_rpc():
    connection = None
    while connection is None:
        try:
            connection = await aio_pika.connect_robust(
                host="127.0.0.1",
                login="mythic_user",
                password="mythic_password",
                virtualhost="mythic_vhost",
            )
            channel = await connection.channel()
            # get a random queue that only the mythic server will use to listen on to catch all heartbeats
            queue = await channel.declare_queue("c2rpc_queue")
            await channel.set_qos(prefetch_count=50)
            logger.info(" [*] Waiting for messages in connect_and_consume_rpc.")
            try:
                task = queue.consume(
                    partial(rabbit_c2_rpc_callback, channel.default_exchange)
                )
                result = await asyncio.wait_for(task, None)
            except Exception as e:
                logger.exception(
                    "Exception in connect_and_consume_c2_rpc .consume: {}".format(
                        str(e)
                    )
                )
                # print("Exception in connect_and_consume .consume: {}".format(str(e)))
        except (ConnectionError, ConnectionRefusedError) as c:
            logger.error("Connection to rabbitmq failed, trying again...")
        except Exception as e:
            logger.exception(
                "Exception in connect_and_consume_c2_rpc connect: {}".format(str(e))
            )
            # print("Exception in connect_and_consume connect: {}".format(str(e)))
        await asyncio.sleep(2)


async def connect_and_consume_heartbeats():
    connection = None
    while connection is None:
        try:
            connection = await aio_pika.connect_robust(
                host="127.0.0.1",
                login="mythic_user",
                password="mythic_password",
                virtualhost="mythic_vhost",
            )
            channel = await connection.channel()
            # declare our exchange
            await channel.declare_exchange(
                "mythic_traffic", aio_pika.ExchangeType.TOPIC
            )
            # get a random queue that only the mythic server will use to listen on to catch all heartbeats
            queue = await channel.declare_queue("", exclusive=True)
            # bind the queue to the exchange so we can actually catch messages
            await queue.bind(exchange="mythic_traffic", routing_key="*.heartbeat.#")
            await channel.set_qos(prefetch_count=20)
            logger.info(" [*] Waiting for messages in connect_and_consume_heartbeats.")
            try:
                task = queue.consume(rabbit_heartbeat_callback)
                result = await asyncio.wait_for(task, None)
            except Exception as e:
                logger.exception(
                    "Exception in connect_and_consume .consume: {}".format(str(e))
                )
                # print("Exception in connect_and_consume .consume: {}".format(str(e)))
        except (ConnectionError, ConnectionRefusedError) as c:
            logger.error("Connection to rabbitmq failed, trying again...")
        except Exception as e:
            logger.exception(
                "Exception in connect_and_consume connect: {}".format(str(e))
            )
            # print("Exception in connect_and_consume connect: {}".format(str(e)))
        await asyncio.sleep(2)


async def send_c2_rabbitmq_message(name, command, message_body, username):
    try:
        connection = await aio_pika.connect(
            host="127.0.0.1",
            login="mythic_user",
            password="mythic_password",
            virtualhost="mythic_vhost",
        )
        channel = await connection.channel()
        # declare our exchange
        exchange = await channel.declare_exchange(
            "mythic_traffic", aio_pika.ExchangeType.TOPIC
        )
        message = aio_pika.Message(
            message_body.encode(), delivery_mode=aio_pika.DeliveryMode.PERSISTENT
        )
        # Sending the message
        await exchange.publish(
            message,
            routing_key="c2.modify.{}.{}.{}".format(
                name, command, base64.b64encode(username.encode()).decode("utf-8")
            ),
        )
        await connection.close()
        return {"status": "success"}
    except Exception as e:
        logger.exception(str(sys.exc_info()[-1].tb_lineno) + " " + str(e))
        # print(str(sys.exc_info()[-1].tb_lineno) + " " + str(e))
        return {"status": "error", "error": "Failed to connect to rabbitmq, refresh"}


async def send_pt_rabbitmq_message(payload_type, command, message_body, username):
    try:
        connection = await aio_pika.connect(
            host="127.0.0.1",
            login="mythic_user",
            password="mythic_password",
            virtualhost="mythic_vhost",
        )
        channel = await connection.channel()
        # declare our exchange
        exchange = await channel.declare_exchange(
            "mythic_traffic", aio_pika.ExchangeType.TOPIC
        )
        message = aio_pika.Message(
            message_body.encode(), delivery_mode=aio_pika.DeliveryMode.PERSISTENT
        )
        # Sending the message
        await exchange.publish(
            message,
            routing_key="pt.task.{}.{}.{}".format(
                payload_type,
                command,
                base64.b64encode(username.encode()).decode("utf-8"),
            ),
        )
        await connection.close()
        return {"status": "success"}
    except Exception as e:
        logger.exception(str(sys.exc_info()[-1].tb_lineno) + " " + str(e))
        # print(str(sys.exc_info()[-1].tb_lineno) + " " + str(e))
        return {"status": "error", "error": "Failed to connect to rabbitmq, refresh"}
