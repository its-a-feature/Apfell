document.title = "Files";
var ready_for_updates = false;
var files_div = new Vue({
    el: '#files_div',
    data: {
        hosts: {"uploads": [], "downloads": []}
    },
    methods: {
        delete_file: function(file_id){
            alertTop("info", "deleting...", 1);
            httpGetAsync("{{http}}://{{links.server_ip}}:{{links.server_port}}{{links.api_base}}/files/" + file_id, delete_file_callback, "DELETE", null);
        },
        export_file_metadata: function(section){
            download_from_memory(section + ".json", btoa(JSON.stringify(this.hosts[section])));
        },
        display_info: function(file){
            file_info_div.file = file;
            $('#file_info_div').modal('show');
        },
        zip_selected_files: function(){
            let selected_files = [];
            for(let i = 0; i < files_div.hosts['downloads'].length; i++){
                if(files_div.hosts['downloads'][i]['selected'] === true){
                    selected_files.push(files_div.hosts['downloads'][i]['agent_file_id']);
                }
            }
            httpGetAsync("{{http}}://{{links.server_ip}}:{{links.server_port}}{{links.api_base}}/files/download/bulk", (response)=>{
                download_from_memory("apfell_downloads.zip", response);
            }, "POST", {'files': selected_files});
        },
        toggle_all: function(){
            let selected = $('#fileselectedall').is(":checked");
            for(let i = 0; i < files_div.hosts['downloads'].length; i++){
                files_div.hosts['downloads'][i]['selected'] = selected;
            }
        }
    },
    delimiters: ['[[',']]']
});
function delete_file_callback(response){
   try{
        var data = JSON.parse(response);
   }catch(error){
        alertTop("danger", "Session expired, please refresh");
   }
   if(data['status'] !== "success"){
        alertTop("danger", data['error']);
   }else{
       for(let i = 0; i < files_div.hosts['uploads'].length; i++){
           if(files_div.hosts['uploads'][i]['id'] === data['id']){
               files_div.hosts['uploads'].splice(i, 1);
               return;
           }
       }
       for(let i = 0; i < files_div.hosts['downloads'].length; i++){
           if(files_div.hosts['downloads'][i]['id'] === data['id']){
               files_div.hosts['downloads'].splice(i, 1);
               return;
           }
       }
   }
}

function startwebsocket_files(){
    let ws = new WebSocket('{{ws}}://{{links.server_ip}}:{{links.server_port}}/ws/files/current_operation');
    ws.onmessage = function(event){
        if (event.data !== ""){
            let file = JSON.parse(event.data);
            //console.log(file);
            file['remote_path'] = "{{http}}://{{links.server_ip}}:{{links.server_port}}{{links.api_base}}/files/download/" + file['agent_file_id'];
            if(file.path.includes("/downloads/")){
                for(let i = 0; i < files_div.hosts['downloads'].length; i++){
                    if(file['id'] === files_div.hosts['downloads'][i]['id']){
                        if(file['deleted'] === true){
                            files_div.hosts['downloads'].splice(i, 1);
                        }else{
                            Vue.set(files_div.hosts['downloads'], i, file);
                        }
                        files_div.$forceUpdate();
                        return;
                    }
                }
                // if we get here, we don't have the file, so add it
                files_div.hosts['downloads'].unshift(file);
                files_div.$forceUpdate();
            }
            else{
                file.upload = JSON.parse(file.upload);
                file['path'] = file['path'].split("/").slice(-1)[0];
                for(let i = 0; i < files_div.hosts['uploads'].length; i++){
                    if(file['id'] === files_div.hosts['uploads'][i]['id']){
                        if(file['deleted'] === true){
                            files_div.hosts['uploads'].splice(i, 1);
                        }else{
                            Vue.set(files_div.hosts['uploads'], i, file);
                        }
                        files_div.$forceUpdate();
                        return;
                    }
                }
                // if we get here, we don't have the file, so add it
                files_div.hosts['uploads'].unshift(file);
                files_div.$forceUpdate();
            }

        }
    };
    ws.onclose = function(){
		wsonclose();
	};
	ws.onerror = function(){
        wsonerror();
	};
    ws.onopen = function(event){
        //console.debug("opened");
    }
}
startwebsocket_files();

var file_info_div = new Vue({
    el: '#file_info_div',
    delimiters: ['[[',']]'],
    data: {
        file: {}
    }
});