exports.list_users = function(task, command, params){
	let all_users = [];
	let method = "api";
	let gid = -1;
	let groups = false;
	if(params.length > 0){
	    let data = JSON.parse(params);
        if(data.hasOwnProperty('method') && data['method'] !== ""){
            method = data['method'];
        }
        if(data.hasOwnProperty('gid') && data['gid'] !== ""){
            gid = data['gid'];
        }
        if(data.hasOwnProperty("groups") && data['groups'] !== ""){
            groups = data['groups'];
        }
	}
    if(method === "api"){
        ObjC.import('Collaboration');
        ObjC.import('CoreServices');
        //ObjC.bindFunction('CFMakeCollectable', ['id', ['void*']]);
        if(gid < 0){
            let defaultAuthority = $.CSGetLocalIdentityAuthority();
            let identityClass = 2;
            if(groups){
                all_users = {}; // we will want to do a dictionary so we can group the members by their GID
            }
            else{
                identityClass = 1; //enumerate users
            }
            let query = $.CSIdentityQueryCreate($(), identityClass, defaultAuthority);
            let error = Ref();
            $.CSIdentityQueryExecute(query, 0, error);
            let results = $.CSIdentityQueryCopyResults(query);
            let numResults = parseInt($.CFArrayGetCount(results));
            for(let i = 0; i < numResults; i++){
                let identity = results.objectAtIndex(i);//results[i];
                let idObj = $.CBIdentity.identityWithCSIdentity(identity);
                if(groups){
                    //if we're looking at groups, then we have a different info to print out
                    all_users[idObj.posixGID] = [];
                    let members = idObj.memberIdentities.js;
                    for(let j = 0; j < members.length; j++){
                        let info = {
                            "POSIXName": members[j].posixName.js,
                            "POSIXID":  members[j].posixUID,
                            "LocalAuthority": members[j].authority.localizedName.js,
                            "FullName": members[j].fullName.js,
                            "Emails":  members[j].emailAddress.js,
                            "isHiddenAccount": members[j].isHidden,
                            "Enabled": members[j].isEnabled,
                            "Aliases": ObjC.deepUnwrap(members[j].aliases),
                            "UUID": members[j].UUIDString.js
                        };
                        all_users[idObj.posixGID].push(info);
                    }
                }
                else{
                    let info = {
                            "POSIXName": idObj.posixName.js,
                            "POSIXID":  idObj.posixUID,
                            "LocalAuthority": idObj.authority.localizedName.js,
                            "FullName": idObj.fullName.js,
                            "Emails":  idObj.emailAddress.js,
                            "isHiddenAccount": idObj.isHidden,
                            "Enabled": idObj.isEnabled,
                            "Aliases": ObjC.deepUnwrap(idObj.aliases),
                            "UUID": idObj.UUIDString.js
                        };
                    all_users.push(info);
                }
            }
        }
        else{
            let defaultAuthority = $.CBIdentityAuthority.defaultIdentityAuthority;
            let group = $.CBGroupIdentity.groupIdentityWithPosixGIDAuthority(gid, defaultAuthority);
            let results = group.memberIdentities.js;
            let numResults = results.length;
            for(let i = 0; i < numResults; i++){
                let idObj = results[i];
                let info = {
                            "POSIXName": idObj.posixName.js,
                            "POSIXID":  idObj.posixUID,
                            "LocalAuthority": idObj.authority.localizedName.js,
                            "FullName": idObj.fullName.js,
                            "Emails":  idObj.emailAddress.js,
                            "isHiddenAccount": idObj.isHidden,
                            "Enabled": idObj.isEnabled,
                            "Aliases": ObjC.deepUnwrap(idObj.aliases),
                            "UUID": idObj.UUIDString.js
                        };
                all_users.push(info);
            }
        }
        return {"user_output":JSON.stringify(all_users, null, 2), "completed": true};
	}
	else{
	    return {"user_output":"Method not known", "completed": true, "status": "error"};
	}
};
COMMAND_ENDS_HERE
