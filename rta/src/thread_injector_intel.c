#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>
#include <mach/mach_vm.h>

#define STACK_SIZE 65536
#define CODE_SIZE 128

/*	This shellcode is just an infinite loop	*/
char injectedCode[] =
    "\x90"
    "\x90"
    "\xeb\xfe"
    "\x90"
    "\x90"
    "\x90";

int inject(pid_t pid)
{
    task_t remoteTask;
    mach_error_t kr = 0;

    /**
    * Second - the critical part - we need task_for_pid in order to get the task port of the target
    * pid. This is our do-or-die: If we get the port, we can do *ANYTHING* we want. If we don't, we're
    * #$%#$%.
    */

    kr = task_for_pid(mach_task_self(), pid, &remoteTask);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to call task_for_pid on pid %d: %s. Cannot continue!\n", pid, mach_error_string(kr));
        return (-1);
    }

    mach_vm_address_t remoteStack64 = (vm_address_t)NULL;
    mach_vm_address_t remoteCode64 = (vm_address_t)NULL;
    kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
        return (-2);
    }
    else {
        fprintf(stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
    }
    /**
     * Then we allocate the memory for the thread
     */
    remoteCode64 = (vm_address_t)NULL;
    kr = mach_vm_allocate(remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
        return (-2);
    }

    /**
  	  * Write the (now patched) code
	  */
    kr = mach_vm_write(remoteTask,                 // Task port
                       remoteCode64,               // Virtual Address (Destination)
                       (vm_address_t)injectedCode, // Source
                       sizeof(injectedCode));                      // Length of the source

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
        return (-3);
    }

    /*
	 * Mark code as executable - This also requires a workaround on iOS, btw.
	 */
    kr = vm_protect(remoteTask, remoteCode64, sizeof(injectedCode), FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

    /*
   	 * Mark stack as writable  - not really necessary
	 */
    kr = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to set memory permissions for remote thread: Error %s\n", mach_error_string(kr));
        return (-4);
    }

    /*
     * Create thread - This is obviously hardware specific.
     */
    x86_thread_state64_t remoteThreadState64;

    thread_act_t remoteThread;

    memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64));

    remoteStack64 += (STACK_SIZE / 2); // this is the real stack
                                       //remoteStack64 -= 8;  // need alignment of 16

    const char *p = (const char *)remoteCode64;

    remoteThreadState64.__rip = (u_int64_t)(vm_address_t)remoteCode64;

    // set remote Stack Pointer
    remoteThreadState64.__rsp = (u_int64_t)remoteStack64;
    remoteThreadState64.__rbp = (u_int64_t)remoteStack64;

    printf("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p);

    /*
	 * create thread and launch it in one go
	 */

    kr = thread_create_running(remoteTask, x86_THREAD_STATE64,
                               (thread_state_t)&remoteThreadState64, x86_THREAD_STATE64_COUNT, &remoteThread);

    //kr = thread_create(remoteTask, &remoteThread);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to create remote thread: error %s", mach_error_string(kr));
        return (-3);
    }

    // Wait for mach thread to finish
/*    mach_msg_type_number_t thread_state_count = x86_THREAD_STATE64_COUNT;
    for (;;) {
	    kr = thread_get_state(remoteThread, x86_THREAD_STATE64, (thread_state_t)&remoteThreadState64, &thread_state_count);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "Error getting stub thread state: error %s", mach_error_string(kr));
            break;
        }

        if (remoteThreadState64.__rax == 0xD13) {
            printf("Stub thread finished\n");
            kr = thread_terminate(remoteThread);
            if (kr != KERN_SUCCESS) {
                fprintf(stderr, "Error terminating stub thread: error %s", mach_error_string(kr));
            }
            break;
        }
    }*/

   sleep(5);

    return 0;
}

int main(int argc, const char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s _pid_ \n", argv[0]);
        exit(0);
    }

    pid_t pid = atoi(argv[1]);
    inject(pid);
}
