#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>
#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <sys/uio.h>
#include <errno.h>
#include <PrintLog.h>
#define pt_regs user_pt_regs

#define uregs	regs
#define ARM_pc	pc
#define ARM_sp	sp
#define ARM_cpsr	pstate
#define ARM_lr		regs[30]
#define ARM_r0		regs[0]
#ifndef PTRACE_GETREGS
#define PTRACE_GETREGS PTRACE_GETREGSET
#endif
#ifndef PTRACE_SETREGS
#define PTRACE_SETREGS PTRACE_SETREGSET
#endif
#define CPSR_T_MASK (1u<<5)

#define MAX_PATH 512
char libcPath[]="/system/lib64/libc.so";

void ptraceWriteData(pid_t pid,void*addr,const char*data,size_t len){
    size_t i=0;
    for(;i<len;i+=sizeof(long)){
        ptrace(PTRACE_POKETEXT,pid,(long)addr+i,(void*)*(long*)&data[i]);
    }
    // 每次写sizeof(long)字节，直接对齐
}
void ptraceReadData(pid_t pid,void*addr,char*data,size_t len){
    size_t i=0;
    long rdata;
    for(;i<len;i+=sizeof(long)){
        rdata=ptrace(PTRACE_PEEKTEXT,pid,(long)addr+i,NULL);
        *(long*)&data[i]=rdata;
    }
}
void ptraceAttach(pid_t pid){
    if(ptrace(PTRACE_ATTACH,pid,NULL,NULL)==-1){
        printf("[INJECT F]Failed to attach:%d\n",pid);
    }
    int stat=0;
    waitpid(pid,&stat,WUNTRACED);
}
void ptraceGetRegs(pid_t pid,struct pt_regs*regs_addr){
    struct iovec io;
    io.iov_base=regs_addr;
    io.iov_len=sizeof(struct pt_regs);
    if(ptrace(PTRACE_GETREGS,pid,NT_PRSTATUS,&io)==-1){
        printf("Get regs error\n");
    }
}
void ptraceSetRegs(pid_t pid,struct pt_regs*regs_addr){
    struct iovec io;
    io.iov_base = regs_addr;
    io.iov_len = sizeof(struct pt_regs);
    if(ptrace(PTRACE_SETREGS,pid,NT_PRSTATUS,&io)==-1){
        printf("Set regs error\n");
    }
}
void ptraceDetach(pid_t pid){
    ptrace(PTRACE_DETACH,pid,NULL,NULL);
}
void ptraceContinue(pid_t pid){
    if(ptrace(PTRACE_CONT,pid,NULL,NULL)==-1){
        printf("ptrace continue error\n");
    }
}
void *getModuleBaseAddr(pid_t pid,const char*moduleName){
    if(pid==-1)pid=getpid();
    // 通过解析/proc/pid/maps 获得基址
    char filepath[MAX_PATH];
    void*moduleBaseAddr=NULL;
    snprintf(filepath,MAX_PATH,"/proc/%d/maps",pid);
    FILE *f = fopen(filepath,"r");
    char line[MAX_PATH];
    char base[MAX_PATH],name[MAX_PATH];
    size_t cnt,start;
    while(!feof(f)){
        memset(line,0,MAX_PATH);
        memset(name,0,MAX_PATH);
        fgets(line,MAX_PATH,f);
        cnt=0;
        while(line[cnt]!='/')cnt++;
        start=cnt;
        while(line[cnt]){
            name[cnt-start]=line[cnt];
            cnt++;
        }
        name[cnt-start-1]=0;

        if(strncmp(name,moduleName,MAX_PATH))continue;
        memset(base,0,MAX_PATH);
        cnt=0;
        while(line[cnt]!='-'){
            base[cnt]=line[cnt];
            cnt++;
        }
        base[cnt]=0;
        sscanf(base,"%llx",(long long*)(&moduleBaseAddr));
        printf("[INJECT] GotBaseAddr %p of %s\n",moduleBaseAddr,moduleName);
        break;
    }
    fclose(f);
    return moduleBaseAddr;
}
void *getRemoteFuncAddr(pid_t pid,const char *moduleName,void *localFuncAddr){
    void *localModuleAddr,*remoteModuleAddr,*remoteFuncAddr;
    // 通过计算指定函数的偏移量获取目标函数地址
    localModuleAddr = getModuleBaseAddr(-1,moduleName);
    remoteModuleAddr = getModuleBaseAddr(pid,moduleName);
    remoteFuncAddr=(void*)((long)localFuncAddr-(long)localModuleAddr+(long)remoteModuleAddr);
    printf("[INJECT] GotFuncAddr:%p\n",remoteFuncAddr);
    return remoteFuncAddr;
}
void ptraceCall(pid_t pid,void* funcAddr,long*paras,long paraLen,struct pt_regs *regs){

	//检查传入的函数地址和参数
	printf("Function Address: %p\n", funcAddr);
	printf("Parameters: ");
	for (size_t i = 0; i < paraLen; i++) {
		printf("%ld ", paras[i]);
	}
	printf("\n");
	
    // 多于8个参数通过栈传递
    if(paraLen>8){
        regs->ARM_sp-=(paraLen-8)*sizeof(long);
        ptraceWriteData(pid,(void*)regs->ARM_sp,(char*)&paras[6],sizeof(long)*(paraLen-6));
    }
    // 前6个参数通过寄存器传递
    for(size_t i=0;i<8;i++){
        regs->uregs[i]=paras[i];
    }
    // 调用函数
    regs->ARM_pc=(unsigned long long)funcAddr;
    // 判断arm模式还是thumb模式
    if(regs->ARM_pc&1){
        regs->ARM_pc&=~1;
        regs->ARM_cpsr|=CPSR_T_MASK;
    }else{
        regs->ARM_cpsr&=~CPSR_T_MASK;
    }
    regs->ARM_lr=0;
    ptraceSetRegs(pid,regs);
    int stat=0;
    while(stat!=0xb7f){
        ptraceContinue(pid);
        waitpid(pid,&stat,WUNTRACED);
        printf("[INJECT] substatus: %x\n",stat);
    }

    ptraceGetRegs(pid,regs);
	// 检查返回值
    printf("Return Value in r0: %lu\n", regs->uregs[0]);
}
void inject(pid_t pid,const char*libname,const char*funcName){
    struct pt_regs oldRegs;
    struct pt_regs regs;
    long paras[6];
    char realLibPath[PATH_MAX];
    //realpath(libname,realLibPath);
    printf("[INJECT]Real path of lib found:%s\n",realLibPath);

    ptraceAttach(pid);
    // 保存寄存器环境
    ptraceGetRegs(pid,&oldRegs);
    memcpy(&regs,&oldRegs,sizeof(struct pt_regs));
    // 获取mmap地址
    void *mmapAddr = getRemoteFuncAddr(pid,libcPath,(void*)mmap);
    // 调用mmap
    paras[0]=0;
    paras[1]=0x1000;
    paras[2]=PROT_READ|PROT_WRITE|PROT_EXEC;
    paras[3]=MAP_PRIVATE;
    paras[4]=-1;
    paras[5]=0;
    ptraceCall(pid,mmapAddr,paras,6,&regs);
    void *remoteMemAddr=(void*)regs.ARM_r0;
    printf("[INJECT] remote mmaped addr:%p\n",remoteMemAddr);    //remoteMemAddr为0？？？？？？？？？？？？？？？？
    // 调用dlopen
    void *dlopenAddr=getRemoteFuncAddr(pid,libcPath,(void*)dlopen);
    void *dlcloseAddr=getRemoteFuncAddr(pid,libcPath,(void*)dlclose);
    void *dlErrorAddr=getRemoteFuncAddr(pid,libcPath,(void*)dlerror);
    ptraceWriteData(pid,remoteMemAddr,libname,strlen(libname)+1);   // 作为dlopen的参数
    //debug start
    char buf[MAX_PATH];
    memset(buf,0,MAX_PATH);
    ptraceReadData(pid,remoteMemAddr,buf,strlen(libname)+3);
    printf("%s\n",buf);
    //debug end
    paras[0]=(long)remoteMemAddr;
    paras[1]=RTLD_NOW|RTLD_GLOBAL;
    ptraceCall(pid,dlopenAddr,paras,2,&regs);
    void*libBaseAddr=(void*)regs.ARM_r0;
    printf("[INJECT]remote lib base:0x%llx of %s\n",(long long)libBaseAddr,libname);
    // 调用dlsym
    void*dlsymAddr=getRemoteFuncAddr(pid,libcPath,(void*)dlsym);
    ptraceWriteData(pid,remoteMemAddr,funcName,strlen(funcName)+1);
    //debug start
    memset(buf,0,MAX_PATH);
    ptraceReadData(pid,remoteMemAddr,buf,strlen(funcName)+3);
    printf("%s\n",buf);
    //debug end
    paras[0]=(long)libBaseAddr;
    paras[1]=(long)remoteMemAddr;
    ptraceCall(pid,dlsymAddr,paras,2,&regs);
    void*remoteFuncAddr = (void*)regs.ARM_r0;
    printf("[INJECT]addr:0x%llx of func %s\n",(long long)remoteFuncAddr,funcName);
    // 调用目标函数
    ptraceCall(pid,remoteFuncAddr,paras,0,&regs);
    // 恢复寄存器环境
    ptraceSetRegs(pid,&oldRegs);
    ptraceDetach(pid);
}
pid_t findPIdByName(const char *name){
    pid_t pid = -1;
    int pDirId = 0; // process dir id
    FILE *f;
    char filename[MAX_PATH];
    char cmdline[MAX_PATH];
    struct dirent *entry=NULL;
    int cnt;
    if(name==NULL){
        return -1;
    }
    DIR *dir = opendir("/proc");
    if(dir==NULL){
        return -1;
    }
    while((entry=readdir(dir))!=NULL){
        pDirId=atoi(entry->d_name);
        if(pDirId!=0){
            snprintf(filename,MAX_PATH,"/proc/%d/cmdline",pDirId);
            f = fopen(filename,"r");
            if(f){
                fgets(cmdline,sizeof(cmdline),f);
                cnt = (int)strlen(cmdline);
                while(cnt>=0&&cmdline[cnt]!='/')cnt--; // cmdline是完整路径，这里只找最后一个/之后的，就是可执行文件的文件名
                cnt++;
                if(!strncmp(name,&cmdline[cnt],strlen(name))){
                    pid=pDirId;
                    break;
                }
            }
            fclose(f);
        }
    }
    closedir(dir);
    return pid;
}

int main(int argc,char **argv){
	char InjectModuleName[MAX_PATH] = "/data/local/tmp/liblib.so";    // 注入模块全路径
	char RemoteCallFunc[MAX_PATH] = "Java_com_zsh_sharedlibrary_MainActivity_killProcess";              // 注入模块后调用模块函数名称
	char InjectProcessName[MAX_PATH] = "com.zsh.apk_demo";                      // 注入进程名称
    pid_t pid = findPIdByName("com.zsh.apk_demo");
    printf("[INJECT]found pid:%d\r\n",pid);
    inject(pid,InjectModuleName,RemoteCallFunc);
    return 0;
}