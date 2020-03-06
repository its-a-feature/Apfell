from app import apfell, links, use_ssl, db_objects
from app.routes.routes import env
from sanic import response
from sanic_jwt.decorators import scoped, inject_user
import app.database_models.model as db_model
import base64
from app.routes.routes import respect_pivot


async def get_scripts(user):
    try:
        scripts_to_add = {}
        browser_scripts = ""
        support_scripts_to_add = {}
        final_support_scripts = ""
        query = await db_model.operator_query()
        operator = await db_objects.get(query, username=user['username'])
        query = await db_model.operation_query()
        operation = await db_objects.get(query, name=user['current_operation'])
        query = await db_model.browserscript_query()
        # get your own scripts
        operator_scripts = await db_objects.execute(
            query.where((db_model.BrowserScript.operator == operator) & (db_model.BrowserScript.active == True)))
        for s in operator_scripts:
            if s.command is not None:
                scripts_to_add[s.command.id] = s.script
            else:
                support_scripts_to_add[s.name] = s.name + ":" + base64.b64decode(s.script).decode('utf-8') + ","
                # final_support_scripts += s.name + ":" + base64.b64decode(s.script).decode('utf-8') + ","
        # get scripts assigned to the operation
        operation_query = await db_model.browserscriptoperation_query()
        operation_scripts = await db_objects.execute(
            operation_query.where(db_model.BrowserScriptOperation.operation == operation))
        for s in operation_scripts:
            if s.browserscript.command is not None:
                scripts_to_add[
                    s.browserscript.command.id] = s.browserscript.script  # will overwrite a user script if it existed, which is what we want
            else:
                support_scripts_to_add[s.browserscript.name] = s.browserscript.name + ":" + base64.b64decode(
                    s.browserscript.script).decode('utf-8') + ","
                # final_support_scripts += s.name + ":" + base64.b64decode(s.script).decode('utf-8') + ","
        for s, v in scripts_to_add.items():
            browser_scripts += str(s) + ":" + base64.b64decode(v).decode('utf-8') + ","
        for s, v in support_scripts_to_add.items():
            final_support_scripts += v
        return browser_scripts, final_support_scripts
    except Exception as e:
        return "", ""


@apfell.route("/callbacks")
@inject_user()
@scoped('auth:user')
async def callbacks(request, user):
    template = env.get_template('callbacks.html')
    browser_scripts, final_support_scripts = await get_scripts(user)
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https",
                                  ws="wss", config=user['ui_config'], browser_scripts=browser_scripts,
                                  support_scripts=final_support_scripts, view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http",
                                  ws="ws", config=user['ui_config'], browser_scripts=browser_scripts,
                                  support_scripts=final_support_scripts, view_utc_time=user['view_utc_time'])
    return response.html(content)


@apfell.route("/payload_management",methods=['GET'])
@inject_user()
@scoped('auth:user')
async def payload_management(request, user):
    template = env.get_template('payload_management.html')
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https",
                                  ws="wss", config=user['ui_config'], view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http",
                                  ws="ws", config=user['ui_config'], view_utc_time=user['view_utc_time'])
    return response.html(content)


@apfell.route("/analytics", methods=['GET'])
@inject_user()
@scoped('auth:user')
async def analytics(request, user):
    template = env.get_template('analytics.html')
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https",
                                  ws="wss", config=user['ui_config'], view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http",
                                  ws="ws", config=user['ui_config'], view_utc_time=user['view_utc_time'])
    return response.html(content)


@apfell.route("/c2profile_management", methods=['GET'])
@inject_user()
@scoped('auth:user')
async def c2profile_management(request, user):
    template = env.get_template('c2profile_management.html')
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https", ws="wss",
                                  current_operation=user['current_operation'], config=user['ui_config'],
                                  view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http", ws="ws",
                                  current_operation=user['current_operation'], config=user['ui_config'],
                                  view_utc_time=user['view_utc_time'])
    return response.html(content)


@apfell.route("/operations_management", methods=['GET'])
@inject_user()
@scoped('auth:user')
async def operations_management(request, user):
    template = env.get_template('operations_management.html')
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https", ws="wss", admin=user['admin'],
                                  current_operation=user['current_operation'], config=user['ui_config'],
                                  view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http", ws="ws", admin=user['admin'],
                                  current_operation=user['current_operation'], config=user['ui_config'],
                                  view_utc_time=user['view_utc_time'])
    return response.html(content)


@apfell.route("/screencaptures", methods=['GET'])
@inject_user()
@scoped('auth:user')
async def screencaptures(request, user):
    template = env.get_template('screencaptures.html')
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https",
                                  ws="wss", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http",
                                  ws="ws", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    return response.html(content)


@apfell.route("/keylogs", methods=['GET'])
@inject_user()
@scoped('auth:user')
async def keylogs(request, user):
    template = env.get_template('keylogs.html')
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https",
                                  ws="wss", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http",
                                  ws="ws", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    return response.html(content)


@apfell.route("/files", methods=['GET'])
@inject_user()
@scoped('auth:user')
async def files(request, user):
    template = env.get_template('files.html')
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https",
                                  ws="wss", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http",
                                  ws="ws", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    return response.html(content)


@apfell.route("/credentials", methods=['GET'])
@inject_user()
@scoped('auth:user')
async def credentials(request, user):
    template = env.get_template('credentials.html')
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https",
                                  ws="wss", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http",
                                  ws="ws", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    return response.html(content)


@apfell.route("/view_tasks", methods=['GET'])
@inject_user()
@scoped('auth:user')
async def view_tasks(request, user):
    template = env.get_template('view_tasks.html')
    browser_scripts, final_support_scripts = await get_scripts(user)
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https",
                                  ws="wss", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], browser_scripts=browser_scripts,
                                  support_scripts=final_support_scripts, view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http",
                                  ws="ws", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], browser_scripts=browser_scripts,
                                  support_scripts=final_support_scripts, view_utc_time=user['view_utc_time'])
    return response.html(content)


@apfell.route("/tasks/<tid:int>", methods=['GET'])
@inject_user()
@scoped('auth:user')
async def view_shared_task(request, user, tid):
    template = env.get_template('share_task.html')
    browser_scripts, final_support_scripts = await get_scripts(user)
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https",
                                  ws="wss", admin=user['admin'], current_operation=user['current_operation'],
                                  tid=tid, config=user['ui_config'], browser_scripts=browser_scripts,
                                  support_scripts=final_support_scripts, view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http",
                                  ws="ws", admin=user['admin'], current_operation=user['current_operation'],
                                  tid=tid, config=user['ui_config'], browser_scripts=browser_scripts,
                                  support_scripts=final_support_scripts, view_utc_time=user['view_utc_time'])
    return response.html(content)


@apfell.route("/split_callbacks/<cid:int>", methods=['GET'])
@inject_user()
@scoped('auth:user')
async def view_split_callbacks(request, user, cid):
    template = env.get_template('split_callback.html')
    browser_scripts, final_support_scripts = await get_scripts(user)
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https",
                                  ws="wss", admin=user['admin'], current_operation=user['current_operation'],
                                  cid=cid, config=user['ui_config'], browser_scripts=browser_scripts,
                                  support_scripts=final_support_scripts, view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http",
                                  ws="ws", admin=user['admin'], current_operation=user['current_operation'], cid=cid,
                                  config=user['ui_config'], browser_scripts=browser_scripts,
                                  support_scripts=final_support_scripts, view_utc_time=user['view_utc_time'])
    return response.html(content)


@apfell.route("/transform_management", methods=['GET'])
@inject_user()
@scoped('auth:user')
async def transform_management(request, user):
    template = env.get_template('transform_management.html')
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https",
                                  ws="wss", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http",
                                  ws="ws", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    return response.html(content)


@apfell.route("/web_log", methods=['GET'])
@inject_user()
@scoped('auth:user')
async def web_log(request, user):
    template = env.get_template('web_log.html')
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https",
                                  ws="wss", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http",
                                  ws="ws", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    return response.html(content)


@apfell.route("/artifacts_management", methods=['GET'])
@inject_user()
@scoped('auth:user')
async def artifacts_management(request, user):
    template = env.get_template('artifacts_management.html')
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https",
                                  ws="wss", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http",
                                  ws="ws", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    return response.html(content)


@apfell.route("/reporting_artifacts", methods=['GET'])
@inject_user()
@scoped('auth:user')
async def reporting_artifacts(request, user):
    template = env.get_template('reporting_artifacts.html')
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https",
                                  ws="wss", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http",
                                  ws="ws", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    return response.html(content)


@apfell.route("/comments", methods=['GET'])
@inject_user()
@scoped('auth:user')
async def comments(request, user):
    template = env.get_template('comments.html')
    browser_scripts, final_support_scripts = await get_scripts(user)
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https",
                                  ws="wss", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], browser_scripts=browser_scripts,
                                  support_scripts=final_support_scripts, view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http",
                                  ws="ws", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], browser_scripts=browser_scripts,
                                  support_scripts=final_support_scripts, view_utc_time=user['view_utc_time'])
    return response.html(content)


@apfell.route("/manage_browser_scripts", methods=['GET'])
@inject_user()
@scoped('auth:user')
async def manage_browser_scripts(request, user):
    template = env.get_template('browser_scripts.html')
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https",
                                  ws="wss", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http",
                                  ws="ws", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    return response.html(content)


@apfell.route("/live_task_feed", methods=['GET'])
@inject_user()
@scoped('auth:user')
async def live_task_feed(request, user):
    template = env.get_template('live_feed.html')
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https",
                                  ws="wss", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http",
                                  ws="ws", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    return response.html(content)


@apfell.route("/live_event_feed", methods=['GET'])
@inject_user()
@scoped('auth:user')
async def live_event_feed(request, user):
    template = env.get_template('live_event_feed.html')
    if use_ssl:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="https",
                                  ws="wss", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    else:
        content = template.render(links=await respect_pivot(links, request), name=user['username'], http="http",
                                  ws="ws", admin=user['admin'], current_operation=user['current_operation'],
                                  config=user['ui_config'], view_utc_time=user['view_utc_time'])
    return response.html(content)

# add links to these routes at the bottom
links['callbacks'] = apfell.url_for('callbacks')
links['payload_management'] = apfell.url_for('payload_management')
links['analytics'] = apfell.url_for('analytics')
links['c2profile_management'] = apfell.url_for('c2profile_management')
links['operations_management'] = apfell.url_for('operations_management')
links['screencaptures'] = apfell.url_for('screencaptures')
links['keylogs'] = apfell.url_for('keylogs')
links['files'] = apfell.url_for('files')
links['credentials'] = apfell.url_for('credentials')
links['view_tasks'] = apfell.url_for('view_tasks')
links['transform_management'] = apfell.url_for('transform_management')
links['artifacts_management'] = apfell.url_for('artifacts_management')
links['reporting_artifacts'] = apfell.url_for('reporting_artifacts')
links['comments'] = apfell.url_for('comments')
links['manage_browser_scripts'] = apfell.url_for('manage_browser_scripts')
links['web_log'] = apfell.url_for('web_log')
links['live_feed'] = apfell.url_for('live_task_feed')
links['live_event_feed'] = apfell.url_for('live_event_feed')

