export namespace sshterm {
	
	export class FileEntry {
	    name: string;
	    size: number;
	    mode: string;
	    isDir: boolean;
	    modTime: string;
	
	    static createFrom(source: any = {}) {
	        return new FileEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.size = source["size"];
	        this.mode = source["mode"];
	        this.isDir = source["isDir"];
	        this.modTime = source["modTime"];
	    }
	}

}

export namespace store {
	
	export class Server {
	    id: string;
	    name: string;
	    host: string;
	    port: number;
	    user: string;
	    authType: string;
	    password?: string;
	    privateKey?: string;
	    tags?: string;
	    createdAt: string;
	    updatedAt: string;
	
	    static createFrom(source: any = {}) {
	        return new Server(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.host = source["host"];
	        this.port = source["port"];
	        this.user = source["user"];
	        this.authType = source["authType"];
	        this.password = source["password"];
	        this.privateKey = source["privateKey"];
	        this.tags = source["tags"];
	        this.createdAt = source["createdAt"];
	        this.updatedAt = source["updatedAt"];
	    }
	}

}

