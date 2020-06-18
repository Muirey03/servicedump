#include <stdio.h>
extern "C"
{
	#import <sandbox.h>
}

void iterate_launchd_services(bool(^iterator)(const char*))
{
	NSString* const dir = @"/System/Library/LaunchDaemons";
	NSFileManager* fileManager = [NSFileManager defaultManager];
	NSURL* url = [NSURL fileURLWithPath:dir];
	NSArray<NSURLResourceKey>* keys = @[NSURLIsDirectoryKey];
	NSDirectoryEnumerationOptions options = NSDirectoryEnumerationSkipsPackageDescendants |
											NSDirectoryEnumerationSkipsHiddenFiles;
	NSArray<NSURL*>* daemons = [fileManager contentsOfDirectoryAtURL:url
												includingPropertiesForKeys:keys
												options:options
												error:NULL];
	//iterate:
	for (NSURL* itemUrl in daemons)
	{
		NSNumber* isDir = nil;
    	[itemUrl getResourceValue:&isDir forKey:NSURLIsDirectoryKey error:NULL];
		if ([isDir boolValue])
			continue;
		NSDictionary* entry = [NSDictionary dictionaryWithContentsOfURL:itemUrl error:NULL];
		if (!entry || ![entry[@"MachServices"] count])
			continue;
		for (NSString* service in entry[@"MachServices"])
		{
			if (!iterator(service.UTF8String))
				break;
		}
	}
}

#define PROC_ALL_PIDS 1
#define PROC_PIDPATHINFO_MAXSIZE 0x1000
extern "C" int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
extern "C" int proc_pidpath(int pid, void * buffer, uint32_t buffersize);

void iterate_procs(bool(^iterator)(pid_t, const char*))
{
	int procCount = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
	pid_t* pids = (pid_t*)calloc(procCount, sizeof(pid_t));
	procCount = proc_listpids(PROC_ALL_PIDS, 0, pids, procCount * sizeof(pid_t));
	for (uint32_t i = 0; i < procCount; i++)
	{
		char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
		proc_pidpath(pids[i], path, sizeof(path));
		if (!iterator(pids[i], @(path).lastPathComponent.UTF8String) || pids[i] == 0)
			break;
	}
	free((void*)pids);
}

bool lookup_check(pid_t pid, const char* service)
{
	return sandbox_check(pid, "mach-lookup", (enum sandbox_filter_type)(SANDBOX_FILTER_GLOBAL_NAME | SANDBOX_CHECK_NO_REPORT), service) == 0;
}

//finds the pid given a string of the pid or process name
pid_t pidForArg(char* arg)
{
	errno = 0;
	__block pid_t ret = (pid_t)strtol(arg, NULL, 0);
	if (errno == 0)
	{
		int err = kill(ret, 0);
		if (err == -1 && errno == ESRCH)
		{
			fprintf(stderr, "ERROR: process does not exist\n");
			exit(EXIT_FAILURE);
		}
		return ret;
	}
	ret = -1;
	iterate_procs(^(pid_t pid, const char* proc_name){
		if (strcmp(arg, proc_name) == 0)
		{
			ret = pid;
			return false;
		}
		return true;
	});
	if (ret == -1)
	{
		fprintf(stderr, "ERROR: failed to find process with pid or name: %s\n", arg);
		exit(EXIT_FAILURE);
	}
	return ret;
}

int main(int argc, char** argv, char** envp)
{
	if (argc < 2)
	{
		fprintf(stderr, "ERROR: no process provided\n");
		return EXIT_FAILURE;
	}

	if (strcmp(argv[1], "check") == 0)
	{
		if (argc < 3)
		{
			fprintf(stderr, "ERROR: no service provided\n");
			return EXIT_FAILURE;
		}
		char* service = argv[2];
		if (argc > 3)
		{
			pid_t pid = pidForArg(argv[3]);
			printf("(%s mach-lookup \"%s\")\n", lookup_check(pid, service) ? "allow" : "deny", service);
		}
		else
		{
			iterate_procs(^(pid_t pid, const char* proc_name){
				printf("%s: (%s mach-lookup \"%s\")\n", proc_name, lookup_check(pid, service) ? "allow" : "deny", service);
				return true;
			});
		}
	}
	else
	{
		pid_t pid = pidForArg(argv[1]);
		iterate_launchd_services(^(const char* service){
			printf("(%s mach-lookup \"%s\")\n", lookup_check(pid, service) ? "allow" : "deny", service);
			return true;
		});
	}
	
	return 0;
}
