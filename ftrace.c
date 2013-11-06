/*
 * ftrace (Function trace) local execution tracing 
 * <Ryan.Oneill@LeviathanSecurity.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <elf.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>

#define MAX_SYMS 8192 * 2

/*
 * On 32bit systems should be set:
 * export FTRACE_ARCH=32
 */
#define FTRACE_ENV "FTRACE_ARCH"

#define MAX_ADDR_SPACE 256 
#define MAXSTR 512

#define TEXT_SPACE  0
#define DATA_SPACE  1
#define STACK_SPACE 2
#define HEAP_SPACE  3

struct { 
	int attach;
	int verbose;
	int elfinfo;
	int typeinfo; //imm vs. ptr
	int arch;
} opts;

struct elf64 {
	Elf64_Ehdr *ehdr;
        Elf64_Phdr *phdr;
        Elf64_Shdr *shdr;
        Elf64_Sym  *sym;
        Elf64_Dyn  *dyn;

	char *StringTable;
	char *SymStringTable;
};

struct elf32 {
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	Elf32_Shdr *shdr;
	Elf32_Sym  *sym;
	Elf32_Dyn  *dyn;
	
	char *StringTable;
	char *SymStringTable;
	
};

struct address_space {
	unsigned long svaddr;
	unsigned long evaddr;
	unsigned int size;
	int count;
};

struct syms {
	char *name;
	unsigned long value;
};

struct handle {
	char *path;
	char **args;
	uint8_t *map;
	struct elf32 *elf32;
	struct elf64 *elf64;
	struct syms lsyms[MAX_SYMS]; //local syms
	struct syms dsyms[MAX_SYMS]; //dynamic syms
	struct syms psyms[MAX_SYMS]; //plt syms
	int lsc; //lsyms count
	int dsc; // dsyms count
	int psc; // psyms count;
	int pid;
};

int global_pid;

void get_address_space(struct address_space *, int, char *);
void MapElf32(struct handle *);
void MapElf64(struct handle *);

/*
 * A couple of commonly used utility
 * functions for mem allocation
 * malloc, strdup wrappers.
 */

void * HeapAlloc(unsigned int len)
{
	uint8_t *mem = malloc(len);
	if (!mem) {
		perror("malloc");
		exit(-1);
	}
	return mem;
}

char * xstrdup(char *s)
{
	char *p = malloc(strlen(s) + 1);
	strcpy(p, s);
	return p;
}
	
/*
 * ptrace functions
 */

int pid_read(int pid, void *dst, const void *src, size_t len)
{

        int sz = len / sizeof(void *);
        int rem = len % sizeof(void *);
        unsigned char *s = (unsigned char *)src;
        unsigned char *d = (unsigned char *)dst;
        long word;
	
        while (sz-- != 0) {
                word = ptrace(PTRACE_PEEKTEXT, pid, s, NULL);
                if (word == -1 && errno) 
                       	return -1;
         
	       *(long *)d = word;
                s += sizeof(long);
                d += sizeof(long);
        }
        
        return 0;
}


/*
 * Get global/local and dynamic
 * symbol/function information.
 */
int BuildSyms(struct handle *h)
{
	unsigned int i, j, k;
	char *SymStrTable;
	Elf32_Ehdr *ehdr32;
	Elf32_Shdr *shdr32;
	Elf32_Sym  *symtab32;
	Elf64_Ehdr *ehdr64;
	Elf64_Shdr *shdr64;
	Elf64_Sym  *symtab64;
	int st_type;
	
	h->psc = 0;
	h->lsc = 0;
	h->dsc = 0;

	switch(opts.arch) {
		case 32:
			ehdr32 = h->elf32->ehdr;
			shdr32 = h->elf32->shdr;
		
			for (i = 0; i < ehdr32->e_shnum; i++) {
				if (shdr32[i].sh_type == SHT_SYMTAB || shdr32[i].sh_type == SHT_DYNSYM) {
					 
				 	SymStrTable = (char *)&h->map[shdr32[shdr32[i].sh_link].sh_offset]; 
                       			symtab32 = (Elf32_Sym *)&h->map[shdr32[i].sh_offset];
					
                        		for (j = 0; j < shdr32[i].sh_size / sizeof(Elf32_Sym); j++, symtab32++) {
						
						st_type = ELF32_ST_TYPE(symtab32->st_info);
						if (st_type != STT_FUNC)
							continue;

						switch(shdr32[i].sh_type) {
							case SHT_SYMTAB:
								h->lsyms[h->lsc].name = xstrdup(&SymStrTable[symtab32->st_name]);
								h->lsyms[h->lsc].value = symtab32->st_value;
								h->lsc++;
								break;
							case SHT_DYNSYM:
								h->dsyms[h->dsc].name = xstrdup(&SymStrTable[symtab32->st_name]);
								h->lsyms[h->lsc].value = symtab32->st_value;
								h->lsc++;
								break;
						}
                        		}
                		}
			}
			
		        h->elf32->StringTable = (char *)&h->map[shdr32[ehdr32->e_shstrndx].sh_offset];
                        for (i = 0; i < ehdr32->e_shnum; i++) {
                                if (!strcmp(&h->elf32->StringTable[shdr32[i].sh_name], ".plt")) {
                                        for (k = 0, j = 0; j < shdr32[i].sh_size; j += 16) {
                                                if (j >= 16) {
                                                        h->dsyms[k++].value = shdr32[i].sh_addr + j;
                                                }
                                        }
                                        break;
                                }
                        } 
			break;
		case 64:
		    	ehdr64 = h->elf64->ehdr;
                        shdr64 = h->elf64->shdr;
		
                        for (i = 0; i < ehdr64->e_shnum; i++) {
                                if (shdr64[i].sh_type == SHT_SYMTAB || shdr64[i].sh_type == SHT_DYNSYM) {

                                        SymStrTable = (char *)&h->map[shdr64[shdr64[i].sh_link].sh_offset];
                                        symtab64 = (Elf64_Sym *)&h->map[shdr64[i].sh_offset];

                                        for (j = 0; j < shdr64[i].sh_size / sizeof(Elf64_Sym); j++, symtab64++) {
						
					  	st_type = ELF64_ST_TYPE(symtab64->st_info);
						if (st_type != STT_FUNC)
							continue;

                                                switch(shdr64[i].sh_type) {
                                                        case SHT_SYMTAB:
                                                                h->lsyms[h->lsc].name = xstrdup(&SymStrTable[symtab64->st_name]);
                                                                h->lsyms[h->lsc].value = symtab64->st_value;
                                                                h->lsc++;
                                                                break;
                                                        case SHT_DYNSYM:	
                                                                h->dsyms[h->dsc].name = xstrdup(&SymStrTable[symtab64->st_name]);
                                                                h->dsyms[h->dsc].value = symtab64->st_value;
                                                                h->dsc++;
                                                                break;
                                                }
                                        }
                                }
                        }
                        h->elf64->StringTable = (char *)&h->map[shdr64[ehdr64->e_shstrndx].sh_offset];
                        for (i = 0; i < ehdr64->e_shnum; i++) {
                                if (!strcmp(&h->elf64->StringTable[shdr64[i].sh_name], ".plt")) {
                                        for (k = 0, j = 0; j < shdr64[i].sh_size; j += 16) {
                                                if (j >= 16) {
							h->dsyms[k++].value = shdr64[i].sh_addr + j;
                                                }
                                        }
					break;
                                }
                        }
			break;
		}

		return 0;

}

char *getargs(struct user_regs_struct *reg, int pid, struct address_space *addrspace)
{
	unsigned char buf[12];
	int i, c = 0, in_ptr_range = 0;
	char *args[12], *p;
	char tmp[64];
	long val;
	char *string = (char *)HeapAlloc(MAXSTR);
	unsigned int maxstr = MAXSTR;
	unsigned int b;

	/* x86_64 supported only at this point--
	 * We are essentially parsing this
	 * calling convention here:
	     	mov    %rsp,%rbp
 	    	mov    $0x6,%r9d
  	  	mov    $0x5,%r8d
  	       	mov    $0x4,%ecx
  	       	mov    $0x3,%edx
  	       	mov    $0x2,%esi
 	       	mov    $0x1,%edi
  	     	callq  400144 <func>
	*/

	for (in_ptr_range = 0, i = 0; i < 35; i += 5) {
		
		val = reg->rip - i;
		if (pid_read(pid, buf, (void *)val, 8) == -1) {
			fprintf(stderr, "pid_read() failed [%d]: %s\n", pid, strerror(errno));
			exit(-1);
		}
		
		in_ptr_range = 0;
		if (buf[0] == 0x48 && buf[1] == 0x89 && buf[2] == 0xe5) // mov %rsp, %rbp
			break;
		switch((unsigned char)buf[0]) {
			case 0xbf:
				if (opts.typeinfo) {
					for (i = 0; i < 4; i++) {
						if (reg->rdi >= addrspace[i].svaddr && reg->rdi <= addrspace[i].evaddr) {
							in_ptr_range++;
							switch(i) {
								case TEXT_SPACE:
									sprintf(tmp, "(text_ptr *)0x%llx", reg->rdi);
									break;
								case DATA_SPACE:
									sprintf(tmp, "(data_ptr *)0x%llx", reg->rdi);
									break;
								case HEAP_SPACE:
									sprintf(tmp, "(heap_ptr *)0x%llx", reg->rdi);
									break;
								case STACK_SPACE:
									sprintf(tmp, "(stack_ptr *)0x%llx", reg->rdi);
									break;
							}
						}
					}
					if (!in_ptr_range) {
						sprintf(tmp, "0x%llx",reg->rdi);
					}
					args[c++] = xstrdup(tmp);
					break;
				}
				sprintf(tmp, "0x%llx", reg->rdi);
				args[c++] = xstrdup(tmp);
				break;
			case 0xbe:
			        if (opts.typeinfo) {
                                        for (i = 0; i < 4; i++) {
                                                if (reg->rsi >= addrspace[i].svaddr && reg->rsi <= addrspace[i].evaddr) {
                                                        in_ptr_range++;
                                                        switch(i) {
                                                                case TEXT_SPACE:
                                                                        sprintf(tmp, "(text_ptr *)0x%llx", reg->rsi);
                                                                        break;
                                                                case DATA_SPACE:
                                                                        sprintf(tmp, "(data_ptr *)0x%llx", reg->rsi);
                                                                        break;
                                                                case HEAP_SPACE:
                                                                        sprintf(tmp, "(heap_ptr *)0x%llx", reg->rsi);
                                                                        break;
                                                                case STACK_SPACE:
                                                                        sprintf(tmp, "(stack_ptr *)0x%llx", reg->rsi);
                                                                        break;
                                                        }
                                                }
                                        }
                                        if (!in_ptr_range) {
                                                sprintf(tmp, "0x%llx", reg->rsi);
                                        }
					args[c++] = xstrdup(tmp);
					break;
                                }

				sprintf(tmp, "0x%llx", reg->rsi);
				args[c++] = xstrdup(tmp);
				break;
			case 0xba:
	                         if (opts.typeinfo) {
                                        for (i = 0; i < 4; i++) {
                                                if (reg->rdx >= addrspace[i].svaddr && reg->rdx <= addrspace[i].evaddr) {
                                                        in_ptr_range++;
                                                        switch(i) {
                                                                case TEXT_SPACE:
                                                                        sprintf(tmp, "(text_ptr *)0x%llx", reg->rdx);
                                                                        break;
                                                                case DATA_SPACE:
                                                                        sprintf(tmp, "(data_ptr *)0x%llx", reg->rdx);
                                                                        break;
                                                                case HEAP_SPACE:
                                                                        sprintf(tmp, "(heap_ptr *)0x%llx", reg->rdx);
                                                                        break;
                                                                case STACK_SPACE:
                                                                        sprintf(tmp, "(stack_ptr *)0x%llx", reg->rdx);
                                                                        break;
                                                        }
                                                }
                                        }
                                        if (!in_ptr_range) {
                                                sprintf(tmp, "0x%llx", reg->rdx);
                                        }
					args[c++] = xstrdup(tmp);
					break;
                                }

				sprintf(tmp, "0x%llx", reg->rdx);
				args[c++] = xstrdup(tmp);
				break;
			case 0xb9:
                        	if (opts.typeinfo) {
                                        for (i = 0; i < 4; i++) {
                                                if (reg->rcx >= addrspace[i].svaddr && reg->rcx <= addrspace[i].evaddr) {
                                                        in_ptr_range++;
                                                        switch(i) {
                                                                case TEXT_SPACE:
                                                                        sprintf(tmp, "(text_ptr *)0x%llx", reg->rcx);
                                                                        break;
                                                                case DATA_SPACE:
                                                                        sprintf(tmp, "(data_ptr *)0x%llx", reg->rcx);
                                                                        break;
                                                                case HEAP_SPACE:
                                                                        sprintf(tmp, "(heap_ptr *)0x%llx", reg->rcx);
                                                                        break;
                                                                case STACK_SPACE:
                                                                        sprintf(tmp, "(stack_ptr *)0x%llx", reg->rcx);
                                                                        break;
                                                        }
                                                }
                                        }
                                        if (!in_ptr_range) {
                                                sprintf(tmp, "0x%llx", reg->rcx);
                                        }
					args[c++] = xstrdup(tmp);
					break;
                                }

				sprintf(tmp, "0x%llx", reg->rcx);
				args[c++] = xstrdup(tmp);
				break;
			case 0x41:
				switch((unsigned char)buf[1]) {
					case 0xb8:
				        	if (opts.typeinfo) {
                                        		for (i = 0; i < 4; i++) {
                                                		if (reg->r8 >= addrspace[i].svaddr && reg->r8 <= addrspace[i].evaddr) {
                                                        		in_ptr_range++;
                                                        		switch(i) {
                                                                		case TEXT_SPACE:
                                                                        		sprintf(tmp, "(text_ptr *)0x%llx", reg->r8);
                                                                        		break;
                                                                		case DATA_SPACE:
                                                                        		sprintf(tmp, "(data_ptr *)0x%llx", reg->r8);
                                                                        		break;
                                                                		case HEAP_SPACE:
                                                                        		sprintf(tmp, "(heap_ptr *)0x%llx", reg->r8);
                                                                        		break;
                                                                		case STACK_SPACE:
                                                                        		sprintf(tmp, "(stack_ptr *)0x%llx", reg->r8);
                                                                        		break;
                                                        		}
                                                		}
                                        		}
                                        		if (!in_ptr_range) {
                                                		sprintf(tmp, "0x%llx", reg->r8);
                                        		}
							args[c++] = xstrdup(tmp);
							break;
                                		}

						sprintf(tmp, "0x%llx", reg->r8);
						args[c++] = xstrdup(tmp);
						break;
					case 0xb9:
					        if (opts.typeinfo) {
                                                        for (i = 0; i < 4; i++) {
                                                                if (reg->r9 >= addrspace[i].svaddr && reg->r9 <= addrspace[i].evaddr) {
                                                                        in_ptr_range++;
                                                                        switch(i) {
                                                                                case TEXT_SPACE:
                                                                                        sprintf(tmp, "(text_ptr *)0x%llx", reg->r9);
                                                                                        break;
                                                                                case DATA_SPACE:
                                                                                        sprintf(tmp, "(data_ptr *)0x%llx", reg->r9);
                                                                                        break;
                                                                                case HEAP_SPACE:
                                                                                        sprintf(tmp, "(heap_ptr *)0x%llx", reg->r9);
                                                                                        break;
                                                                                case STACK_SPACE:
                                                                                        sprintf(tmp, "(stack_ptr *)0x%llx", reg->r9);
                                                                                        break;
                                                                        }       
                                                                }
                                                        }
                                                        if (!in_ptr_range) {
                                                                sprintf(tmp, "0x%llx", reg->r9);
                                                        }
							args[c++] = xstrdup(tmp);
							break;       
                                                }

						sprintf(tmp, "0x%llx", reg->r9);
						args[c++] = xstrdup(tmp);
						break;
				}
		}
	}

	if (c == 0)
		return NULL;
	b = 0;
	string[0] = '(';
	b++;
	strncpy((char *)&string[1], args[0], maxstr - b - 1);
	b += strlen(args[0]);
	if (b > maxstr) {
		string = realloc((char *)string, maxstr + b + 1);
		maxstr += b + 1;
	}	
	strncat(string, ",", maxstr - b);
	b++;
	for (i = 1; i < c; i++) {
		if (b > maxstr) {
			string = realloc((char *)string, maxstr + b + 1);
                	maxstr += b + 1;
        	}
		strncat(string, args[i], maxstr - b);	
		b += strlen(args[i]);
		if (b > maxstr) {
			string = realloc((char *)string, maxstr + b + 1);
			maxstr += b + 1;
		}
		strncat(string, ",", maxstr - b);
		b++;
	}
	if ((p = strrchr(string, ',')))
		*p = '\0';
	if (b > maxstr) {
		string = realloc((char *)string, maxstr + b + 1);
                maxstr += b + 1;
        }
	strncat(string, ")", maxstr - b);
	*(string + (maxstr - 1)) = '\0';
	
	return string;

}

/*
 * Our main handler function to parse ELF info
 * read instructions, parse them, and print
 * function calls and stack args.
 */
void examine_process(struct handle *h)
{
	
	int i, count, status;
	struct user_regs_struct pt_reg;
	long esp, eax, ebx, edx, ecx, esi, edi, eip;
	uint8_t buf[8];
	unsigned long vaddr;
	unsigned int offset;
	char *argstr;
	struct address_space *addrspace = (struct address_space *)HeapAlloc(sizeof(struct address_space) * MAX_ADDR_SPACE); 
	
	/*
	 * Allocate ELF structure for
	 * specified Arch, and map in 
	 * the executable file for the
	 * file we are examining.
	 */
	switch(opts.arch) {
		case 32:
			h->elf32 = HeapAlloc(sizeof(struct elf32));
			h->elf64 = NULL;
			MapElf32(h);
			break;
		case 64:
			h->elf64 = HeapAlloc(sizeof(struct elf64));
			h->elf32 = NULL;
			MapElf64(h);
			break;
	}

	/*
	 * Build ELF Symbol information
	 */
	BuildSyms(h);
	
	/* 
	 * Retrieve the program address space layout
	 * to aid in our pointer/type prediction
	 */
	get_address_space((struct address_space *)addrspace, h->pid, h->path);

	if (opts.verbose) {
		printf("[+] Printing Symbol Information!\n\n");
		for (i = 0; i < h->lsc; i++) {
			if (h->lsyms[i].name == NULL)
				printf("UNKNOWN: 0x%lx\n", h->lsyms[i].value);
			else
				printf("%s 0x%lx\n", h->lsyms[i].name, h->lsyms[i].value);
		}
		for (i = 0; i < h->dsc; i++) {
			if (h->lsyms[i].name == NULL)
				printf("UNKNOWN: 0x%lx\n", h->lsyms[i].value);
			else
				printf("%s 0x%lx\n", h->dsyms[i].name, h->dsyms[i].value);
		}
		printf("[+] Printing the address space layout\n");
		printf("0x%lx-0x%lx %s [text]\n", addrspace[TEXT_SPACE].svaddr, addrspace[TEXT_SPACE].evaddr, h->path);
		printf("0x%lx-0x%lx %s [data]\n", addrspace[DATA_SPACE].svaddr, addrspace[DATA_SPACE].evaddr, h->path);
		printf("0x%lx-0x%lx %s [heap]\n", addrspace[HEAP_SPACE].svaddr, addrspace[HEAP_SPACE].evaddr, h->path);
		printf("0x%lx-0x%lx %s [stack]\n",addrspace[STACK_SPACE].svaddr, addrspace[STACK_SPACE].evaddr, h->path); 
	}
	
	printf("\n[+] Function tracing begins here:\n");
        for (;;) {

                ptrace (PTRACE_SINGLESTEP, h->pid, NULL, NULL);
                wait (&status);
                count++;

                if (WIFEXITED (status))
                	break;

                ptrace (PTRACE_GETREGS, h->pid, NULL, &pt_reg);
		
#ifdef __x86_64__
		esp = pt_reg.rsp;
		eip = pt_reg.rip;
		eax = pt_reg.rax;
		ebx = pt_reg.rbx;
		ecx = pt_reg.rcx;
		edx = pt_reg.rdx;
		esi = pt_reg.rsi;
		edi = pt_reg.rdi;
#else
		esp = pt_reg.esp;
		eip = pt_reg.eip;
		eax = pt_reg.rax;
		ebx = pt_reg.ebx;
		ecx = pt_reg.ecx;
		edx = pt_reg.edx;
		esi = pt_reg.esi;
		edi = pt_reg.edi;
#endif
		
		if (pid_read(h->pid, buf, (void *)eip, 8) < 0) {
			fprintf(stderr, "pid_read() failed: %s\n", strerror(errno));
			exit(-1);
		}
		
		if (buf[0] == 0xe8) {
			offset = buf[1] + (buf[2] << 8) + (buf[3] << 16) + (buf[4] << 24);
			vaddr = eip + offset + 5; 
			vaddr &= 0xffffffff;

			for (i = 0; i < h->lsc; i++) {
				if (vaddr == h->lsyms[i].value) {
					argstr = getargs(&pt_reg, h->pid, addrspace);
					if (argstr == NULL) 
						printf("LOCAL_call@0x%lx: %s()\n", h->lsyms[i].value, h->lsyms[i].name);
					else
						printf("LOCAL_call@0x%lx: %s%s\n", h->lsyms[i].value, h->lsyms[i].name, argstr);
				}
				
			}
			for (i = 0; i < h->dsc; i++) {
				if (vaddr == h->dsyms[i].value) {
					argstr = getargs(&pt_reg, h->pid, addrspace);
					if (argstr == NULL)
						printf("LOCAL_call@0x%lx: %s()\n", h->dsyms[i].value, h->dsyms[i].name);
					else
						printf("PLT_call@0x%lx: %s%s\n", h->dsyms[i].value, h->dsyms[i].name, argstr);
				}
			}
		}
		
				
	}


}

void MapElf32(struct handle *h)
{
	int fd;
	struct stat st;
	
	if ((fd = open(h->path, O_RDONLY)) < 0) {
		fprintf(stderr, "Unable to open %s: %s\n", h->path, strerror(errno));
		exit(-1);
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		exit(-1);
	}

	h->map = (uint8_t *)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (h->map == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}

	h->elf32->ehdr = (Elf32_Ehdr *)h->map;
	h->elf32->shdr = (Elf32_Shdr *)(h->map + h->elf32->ehdr->e_shoff);
	h->elf32->phdr = (Elf32_Phdr *)(h->map + h->elf32->ehdr->e_phoff);

}

/*
 * Parse /proc/<pid>/maps to get address space layout
 * of executable text/data, heap, stack.
 */
void get_address_space(struct address_space *addrspace, int pid, char *path)
{
	char tmp[64], buf[256];
        char *p, addrstr[32];
	FILE *fd;
        int i, lc;
	
        snprintf(tmp, 64, "/proc/%d/maps", pid);

        if ((fd = fopen(tmp, "r")) == NULL) {
                fprintf(stderr, "Unable to open %s: %s\n", tmp, strerror(errno));
                exit(-1);
        }
	
        for (lc = 0, p = buf; fgets(buf, sizeof(buf), fd) != NULL; lc++) {
		/*
		 * Get executable text and data
	 	 * segment addresses.
		 */
		if ((char *)strchr(buf, '/') && lc == 0) {
			for (i = 0; *p != '-'; i++, p++) 
				addrstr[i] = *p;
			addrstr[i] = '\0';
			addrspace[TEXT_SPACE].svaddr = strtoul(addrstr, NULL, 16);
			for (p = p + 1, i = 0; *p != 0x20; i++, p++)
				addrstr[i] = *p;
			addrstr[i] = '\0';
			addrspace[TEXT_SPACE].evaddr = strtoul(addrstr, NULL, 16);
			addrspace[TEXT_SPACE].size = addrspace[TEXT_SPACE].evaddr - addrspace[TEXT_SPACE].svaddr;
		}
		
		if ((char *)strchr(buf, '/') && strstr(buf, path) && strstr(buf, "rw-p")) {
			for (i = 0, p = buf; *p != '-'; i++, p++)
				addrstr[i] = *p;				
			addrstr[i] = '\0';
			addrspace[DATA_SPACE].svaddr = strtoul(addrstr, NULL, 16);
			for (p = p + 1, i = 0; *p != 0x20; i++, p++)
                                addrstr[i] = *p;
                        addrstr[i] = '\0';
                        addrspace[DATA_SPACE].evaddr = strtoul(addrstr, NULL, 16);
                        addrspace[DATA_SPACE].size = addrspace[DATA_SPACE].evaddr - addrspace[DATA_SPACE].svaddr;
		}
		/*
		 * Get the heap segment address layout
	 	 */
		if (strstr(buf, "[heap]")) {
			for (i = 0, p = buf; *p != '-'; i++, p++)
				addrstr[i] = *p;
			addrstr[i] = '\0';
			addrspace[HEAP_SPACE].svaddr = strtoul(addrstr, NULL, 16);
			for (p = p + 1, i = 0; *p != 0x20; i++, p++)
				addrstr[i] = *p;
			addrstr[i] = '\0';
			addrspace[HEAP_SPACE].evaddr = strtoul(addrstr, NULL, 16);
			addrspace[HEAP_SPACE].size = addrspace[HEAP_SPACE].evaddr - addrspace[DATA_SPACE].svaddr;
		}
		/*
		 * Get the stack segment layout
		 */
		if (strstr(buf, "[stack]")) {
			 for (i = 0, p = buf; *p != '-'; i++, p++)
                                addrstr[i] = *p;
                        addrstr[i] = '\0';
                        addrspace[STACK_SPACE].svaddr = strtoul(addrstr, NULL, 16);
                        for (p = p + 1, i = 0; *p != 0x20; i++, p++)
                                addrstr[i] = *p;
                        addrstr[i] = '\0';
                        addrspace[STACK_SPACE].evaddr = strtoul(addrstr, NULL, 16);
                        addrspace[STACK_SPACE].size = addrspace[STACK_SPACE].evaddr - addrspace[STACK_SPACE].svaddr;
                }
	 }
}

char * get_path(int pid)
{
	char tmp[64], buf[256];
	char path[256], *ret, *p;
	FILE *fd;
	int i;
	
	snprintf(tmp, 64, "/proc/%d/maps", pid);
	
	if ((fd = fopen(tmp, "r")) == NULL) {
		fprintf(stderr, "Unable to open %s: %s\n", tmp, strerror(errno));
		exit(-1);
	}
	
	if (fgets(buf, sizeof(buf), fd) == NULL)
		return NULL;
	p = strchr(buf, '/');
	if (!p)
		return NULL;
	for (i = 0; *p != '\n' && *p != '\0'; p++, i++)
		path[i] = *p;
	path[i] = '\0';
	ret = (char *)HeapAlloc(i + 1);
	strcpy(ret, path);
	if (strstr(ret, ".so")) {
		fprintf(stderr, "Process ID: %d appears to be a shared library; file must be an executable. (path: %s)\n",pid, ret);
		exit(-1);
	}
	return ret;
}

int validate_em_type(char *path)
{
	int fd;
	uint8_t *mem, *p;
	unsigned int value;
	Elf64_Ehdr *ehdr64;
	Elf32_Ehdr *ehdr32;

	if ((fd = open(path, O_RDONLY)) < 0) {
		fprintf(stderr, "Could not open %s: %s\n", path, strerror(errno));
		exit(-1);
	}
	
	mem = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}
	
	switch (opts.arch) {
		case 32:
			ehdr32 = (Elf32_Ehdr *)mem;
			if (ehdr32->e_machine != EM_386)
				return 0;
			break;
		case 64:
			ehdr64 = (Elf64_Ehdr *)mem;
			if (ehdr64->e_machine != EM_X86_64 && ehdr64->e_machine != EM_IA_64)
				return 0;
			break;
	}
	return 1;
}

	
void MapElf64(struct handle *h)
{
	int fd;
        struct stat st;

        if ((fd = open(h->path, O_RDONLY)) < 0) {
                fprintf(stderr, "Unable to open %s: %s\n", h->path, strerror(errno));
                exit(-1);
        }

        if (fstat(fd, &st) < 0) {
                perror("fstat");
                exit(-1);
        }

        h->map = (uint8_t *)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (h->map == MAP_FAILED) {
                perror("mmap");
                exit(-1);
        }

        h->elf64->ehdr = (Elf64_Ehdr *)h->map;
        h->elf64->shdr = (Elf64_Shdr *)(h->map + h->elf64->ehdr->e_shoff);
        h->elf64->phdr = (Elf64_Phdr *)(h->map + h->elf64->ehdr->e_phoff);


}
void sighandle(int sig)
{
	fprintf(stdout, "Caught signal ctrl-C, detaching...\n");
	ptrace(PTRACE_DETACH, global_pid, NULL, NULL);
	exit(0);
}


int main(int argc, char **argv, char **envp)
{
	int opt, i, pid, status, skip_getopt = 0;
	struct handle handle;
	char **p, *arch;
	
        struct sigaction act;
        sigset_t set;
        act.sa_handler = sighandle;
        sigemptyset (&act.sa_mask);
        act.sa_flags = 0;
        sigaction (SIGINT, &act, NULL);
        sigemptyset (&set);
        sigaddset (&set, SIGINT);

	if (argc < 2) {
usage:
		printf("Usage: %s [-p <pid>] [-tve] <prog>\n", argv[0]);
		printf("[-p] Trace by PID\n");
		printf("[-t] Type detection of function args\n");
		printf("[-r] Register values\n");
		printf("[-v] Verbose output\n");
		printf("[-e] Misc. ELF info. Not yet incorperated\n");
		exit(0);
	}
	
	if (argc == 2 && argv[1][0] == '-')
		goto usage;

	memset(&opts, 0, sizeof(opts));
	
	opts.arch = 64; // default
	arch = getenv(FTRACE_ENV);
	if (arch != NULL) {
		switch(atoi(arch)) {
			case 32:
				opts.arch = 32;
				break;
			case 64:
				opts.arch = 64;
				break;
			default:
				fprintf(stderr, "Unknown architecture: %s\n", arch);
				break;
		}
	}
	
	if (argv[1][0] != '-') {
		
		handle.path = xstrdup(argv[1]);
		handle.args = (char **)HeapAlloc(sizeof(char *) * argc - 1);
		
		for (i = 0, p = &argv[1]; i != argc - 1; p++, i++) {
			*(handle.args + i) = xstrdup(*p);
		}
		*(handle.args + i) = NULL;
		skip_getopt = 1;
			
	} else {
		handle.path = xstrdup(argv[2]);
		handle.args = (char **)HeapAlloc(sizeof(char *) * argc - 1);
		
		for (i = 0, p = &argv[2]; i != argc - 2; p++, i++) {
			*(handle.args + i) = xstrdup(*p);
		}
		*(handle.args + i) = NULL;
	}

		
	if (skip_getopt)
		goto begin;

	while ((opt = getopt(argc, argv, "htvep:")) != -1) {
		switch(opt) {
			case 'v':
				opts.verbose++;
				break;
			case 'e':
				opts.elfinfo++;
				break;
			case 't':
				opts.typeinfo++;
				break;
			case 'p':
				opts.attach++;
				handle.pid = atoi(optarg);
				break;
			case 'h':
				goto usage;
			default:
				printf("Unknown option\n");
				exit(0);
		}
	} 
	
begin:
	if (opts.verbose) {
		switch(opts.arch) {
			case 32:
				printf("[+] 32bit ELF mode enabled!\n");
				break;
			case 64:
				printf("[+] 64bit ELF mode enabled!\n");
				break;
		}
		if (opts.typeinfo) 
			printf("[+] Pointer type prediction enabled\n");
	}

	/*
	 * We are not attaching, but rather executing
	 * in this first instance
	 */
	if (!opts.attach) {
		
		if (!validate_em_type(handle.path)) {
			printf("[!] ELF Architecture is set to %d, the target %s is not the same architecture\n", opts.arch, handle.path);
			exit(-1);
		}
	
		if ((pid = fork()) < 0) {
			perror("fork");
			exit(-1);
		}
		
		
		if (pid == 0) {
			if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
              			perror("PTRACE_TRACEME");
              			exit(-1);
			}
		  	execve(handle.path, handle.args, envp);
			exit(0);
		}
		waitpid(0, &status, WNOHANG);
		handle.pid = pid;
		global_pid = pid;
		examine_process(&handle);
		goto done;
	}

	/*  
	 * In this second instance we trace an
	 * existing process id.
	 */
	if (ptrace(PTRACE_ATTACH, handle.pid, NULL, NULL) == -1) {
		perror("PTRACE_ATTACH");
		exit(-1);
	}
	handle.path = get_path(handle.pid);
        if (!validate_em_type(handle.path)) {
        	printf("[!] ELF Architecture is set to %d, the target %s is not the same architecture\n", opts.arch, handle.path);
        	exit(-1);
       	}

	waitpid(handle.pid, &status, WUNTRACED);
	global_pid = handle.pid;
	examine_process(&handle);

	
done:
	ptrace(PTRACE_DETACH, handle.pid, NULL, NULL);
	exit(0);

}
	

