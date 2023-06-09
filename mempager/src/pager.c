#include "pager.h"

#include <sys/mman.h>

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "mmu.h"


// inicio da implementação da estrutura de dados

struct dlist {
    struct dnode *head;
    struct dnode *tail;
    int count;
};

struct dnode {
    struct dnode *prev;
    struct dnode *next;
    void *data;
};

/*struct slist {
    struct snode *head;
    struct snode *tail;
    int count;
};

struct snode {
    struct snode *prev;
    struct snode *next;
    void *data;
};*/

typedef void (*dlist_data_func)(void *data);

int dlist_empty(struct dlist *dl) {
    int ret;
    if(dl->head == NULL) {
        assert(dl->tail == NULL);
        assert(dl->count == 0);
        ret = 1;
    } else {
        assert(dl->tail != NULL);
        assert(dl->count > 0);
        ret = 0;
    }
    return ret;
}

//struct dlist *dlist_create(void);
struct dlist *dlist_create(void) {

    struct dlist *dl = malloc(sizeof(struct dlist));
    assert(dl);
    dl->head = NULL;
    dl->tail = NULL;
    dl->count = 0;
    return dl;
}

void *dlist_pop_right(struct dlist *dl) {

    if(dlist_empty(dl)) return NULL;

    void *data;
    struct dnode *node;

    node = dl->tail;

    dl->tail = node->prev;
    if(dl->tail == NULL) dl->head = NULL;
    if(node->prev) node->prev->next = NULL;

    data = node->data;
    free(node);

    dl->count--;
    assert(dl->count >= 0);

    return data;
}

//void dlist_destroy(struct dlist *dl, dlist_data_func);
void dlist_destroy(struct dlist *dl, dlist_data_func cb) {

    while(!dlist_empty(dl)) {
        void *data = dlist_pop_right(dl);
        if(cb) cb(data);
    }
    free(dl);
}

//void *dlist_pop_right(struct dlist *dl);
/*void *dlist_pop_right(struct dlist *dl) {
    if(dlist_empty(dl)) return NULL;

    void *data;
    struct dnode *node;

    node = dl->tail;

    dl->tail = node->prev;
    if(dl->tail == NULL) dl->head = NULL;
    if(node->prev) node->prev->next = NULL;

    data = node->data;
    free(node);

    dl->count--;
    assert(dl->count >= 0);

    return data;
}*/

//void *dlist_push_right(struct dlist *dl, void *data);
void *dlist_push_right(struct dlist *dl, void *data) {

    struct dnode *node = malloc(sizeof(struct dnode));
    assert(node);

    node->data = data;
    node->prev = dl->tail;
    node->next = NULL;

    if(dl->tail) dl->tail->next = node;
    dl->tail = node;

    if(dl->head == NULL) dl->head = node;

    dl->count++;

    return data;
}

//int dlist_empty(struct dlist *dl);
/*int dlist_empty(struct dlist *dl) {
    int ret;
    if(dl->head == NULL) {
        assert(dl->tail == NULL);
        assert(dl->count == 0);
        ret = 1;
    } else {
        assert(dl->tail != NULL);
        assert(dl->count > 0);
        ret = 0;
    }
    return ret;
}*/

/* gets the data at index =idx.  =idx can be negative. */
//void * dlist_get_index(const struct dlist *dl, int idx);
void * dlist_get_index(const struct dlist *dl, int idx) {

    struct dnode *curr;
    if(idx >= 0) {
        curr = dl->head;
        while(curr && idx--) curr = curr->next;
    } else {
        curr = dl->tail;
        while(curr && ++idx) curr = curr->prev;
    }
    if(!curr) return NULL;
    return curr->data;
}
// fim das implementações da lista 

// estruturas do paginador

typedef struct {
    int isvalid;
    int frame_number;
    int block_number;
    int dirty; //when the page is dirty, it must to be wrote on the disk before swaping it
    intptr_t vaddr;
} Page;

typedef struct {
    pid_t pid;
    struct dlist *pages;
} PageTable;

typedef struct {
    pid_t pid;
    int accessed; //to be used by second change algorithm
    Page *page;
} FrameNode;

typedef struct {
    int nframes;
    int page_size;
    int sec_chance_index;
    FrameNode *frames;
} FrameTable;

typedef struct {
    int used; //1 if the page was copied to the disk, 0 otherwise
    Page *page;
} BlockNode;

typedef struct {
    int nblocks;
    BlockNode *blocks;
} BlockTable;

FrameTable frame_table;
BlockTable block_table;
struct dlist *page_tables;

//funcoes auxiliares

//int get_new_frame();
int get_new_frame() {

    for(int i = 0; i < frame_table.nframes; i++) {
        if(frame_table.frames[i].pid == -1) return i;
    }
    return -1;
}

//int get_new_block();
int get_new_block() {

    for(int i = 0; i < block_table.nblocks; i++) {
        if(block_table.blocks[i].page == NULL) return i;
    }
    return -1;
}
//PageTable* find_page_table(pid_t pid);
PageTable* find_page_table(pid_t pid) {

    for(int i = 0; i < page_tables->count; i++) {
        PageTable *pt = dlist_get_index(page_tables, i);
        if(pt->pid == pid) return pt;
    }
    printf("error in find_page_table: Pid not found\n");
    exit(-1);
}
//Page* get_page(PageTable *pt, intptr_t vaddr);
Page* get_page(PageTable *pt, intptr_t vaddr) {
    
    for(int i=0; i < pt->pages->count; i++) {
        Page *page = dlist_get_index(pt->pages, i);
        if(vaddr >= page->vaddr && vaddr < (page->vaddr + frame_table.page_size)) return page;
    }
    return NULL;
}
pthread_mutex_t locker;

//funcoes do paginador de memoria

/*void pager_init(int nframes, int nblocks) {
    pthread_mutex_lock(&locker);
    frame_table.nframes = nframes;
    frame_table.page_size = sysconf(_SC_PAGESIZE);
    frame_table.sec_chance_index = 0;

    frame_table.frames = malloc(nframes * sizeof(FrameNode));
    for(int i = 0; i < nframes; i++) {
        frame_table.frames[i].pid = -1;
    }

    block_table.nblocks = nblocks;
    block_table.blocks = malloc(nblocks * sizeof(BlockNode));
    for(int i = 0; i < nblocks; i++) {
        block_table.blocks[i].used = 0;
    }
    page_tables = dlist_create();
    pthread_mutex_unlock(&locker);
}*/

void pager_init(int nframes, int nblocks) {

    // Bloqueia o mutex para acesso exclusivo às estruturas de dados
    pthread_mutex_lock(&locker);
    // Define o número de frames físicos disponíveis
    frame_table.nframes = nframes;
    // Obtém o tamanho da página em bytes do sistema
    frame_table.page_size = sysconf(_SC_PAGESIZE);
    // Inicializa o índice do algoritmo de substituição de página
    frame_table.sec_chance_index = 0;
    // Aloca memória para o array de frames
    frame_table.frames = (FrameNode*)malloc(nframes * sizeof(FrameNode));

    //setando todos os frames como -1
    // Inicializa todos os frames com valor -1 para indicar que estão vazios
    for (int i = 0; i < nframes; i++) {
        frame_table.frames[i].pid = -1;
    }
    // Define o número de blocos disponíveis na memória secundária
    block_table.nblocks = nblocks;
    // Aloca memória para o array de blocos
    block_table.blocks = (BlockNode*)malloc(nblocks * sizeof(BlockNode));

    //setando todos os blocos como não utilizados 
    // Inicializa todos os blocos com valor 0 para indicar que não estão sendo utilizados
    for (int i = 0; i < nblocks; i++) {
        block_table.blocks[i].used = 0;
    }

    page_tables = dlist_create(); // Cria a lista para armazenar as tabelas de páginas

    pthread_mutex_unlock(&locker); // Desbloqueia o mutex para permitir acesso concorrente às estruturas de dados
}


/*void pager_create(pid_t pid) {
    pthread_mutex_lock(&locker);
    PageTable *pt = (PageTable*) malloc(sizeof(PageTable));
    pt->pid = pid;
    pt->pages = dlist_create();

    dlist_push_right(page_tables, pt);
    pthread_mutex_unlock(&locker);
}*/

void pager_create(pid_t pid) {

    pthread_mutex_lock(&locker);// Bloqueia o mutex para acesso exclusivo às estruturas de dados
    // Criar uma nova estrutura PageTable
    PageTable *page_t = (PageTable*) malloc(sizeof(PageTable));
    page_t->pid = pid;
    page_t->pages = dlist_create();
    // Adicionar a nova PageTable à lista de page_tables
    dlist_push_right(page_tables, page_t);
    pthread_mutex_unlock(&locker);// Desbloqueia o mutex para permitir acesso concorrente às estruturas de dados

}


/*void *pager_extend(pid_t pid) {
    pthread_mutex_lock(&locker);
    int block_no = get_new_block();

    //there is no blocks available anymore
    if(block_no == -1) {
        pthread_mutex_unlock(&locker);
        return NULL;
    }

    PageTable *pt = find_page_table(pid); 
    Page *page = (Page*) malloc(sizeof(Page));
    page->isvalid = 0;
    page->vaddr = UVM_BASEADDR + pt->pages->count * frame_table.page_size;
    page->block_number = block_no;
    dlist_push_right(pt->pages, page);

    block_table.blocks[block_no].page = page;

    pthread_mutex_unlock(&locker);
    return (void*)page->vaddr;
}*/

void *pager_extend(pid_t pid) {

    pthread_mutex_lock(&locker); // Adquire o bloqueio do mutex para garantir exclusão mútua

    int n_block = get_new_block(); // Obtém um bloco disponível na tabela de blocos

    if (n_block == -1) { // Não há mais blocos disponíveis
        pthread_mutex_unlock(&locker); // Libera o bloqueio do mutex antes de retornar
        return NULL; // Retorna NULL para indicar falha na alocação
    }

    PageTable *page_t = find_page_table(pid); // Encontra a tabela de páginas do processo

    Page *page = (Page*)malloc(sizeof(Page)); // Aloca memória para a nova página

    page->isvalid = 0;
    page->vaddr = UVM_BASEADDR + page_t->pages->count * frame_table.page_size;
    page->block_number = n_block;

    dlist_push_right(page_t->pages, page); // Insere a nova página na lista de páginas da tabela de páginas

    block_table.blocks[n_block].page = page; // Atualiza a tabela de blocos com a referência à nova página

    pthread_mutex_unlock(&locker); // Libera o bloqueio do mutex antes de retornar
    return (void*)page->vaddr; // Retorna o endereço virtual da nova página
}



/*void *pager_extend(pid_t pid) {
    pthread_mutex_lock(&locker); // Adquire o bloqueio do mutex para garantir exclusão mútua

    int block_no = get_new_block(); // Obtém um bloco disponível na tabela de blocos

    // Não há mais blocos disponíveis
    if (block_no == -1) {
        pthread_mutex_unlock(&locker); // Libera o bloqueio do mutex antes de retornar
        return NULL; // Retorna NULL para indicar falha na alocação
    }

    PageTable *pt = find_page_table(pid); // Encontra a tabela de páginas do processo
    Page *page = (Page*) malloc(sizeof(Page)); // Aloca memória para a nova página
    page->isvalid = 0; // Define a página como inválida
    page->vaddr = UVM_BASEADDR + pt->pages->count * frame_table.page_size; // Calcula o endereço virtual da página
    page->block_number = block_no; // Atribui o número do bloco à página

    // Atualiza a tabela de blocos com a referência à nova página
    block_table.blocks[block_no].page = page;

    pthread_mutex_unlock(&locker); // Libera o bloqueio do mutex antes de retornar
    return (void*) page->vaddr; // Retorna o endereço virtual da nova página
}*/

/*
int second_chance() {
    FrameNode *frames = frame_table.frames;
    int frame_to_swap = -1;

    while(frame_to_swap == -1) {
        int index = frame_table.sec_chance_index;
        if(frames[index].accessed == 0) {
            frame_to_swap = index;
        } else {
            frames[index].accessed = 0;
        }
        frame_table.sec_chance_index = (index + 1) % frame_table.nframes;
    }

    return frame_to_swap;
}*/

int second_chance() {

    FrameNode *frames = frame_table.frames;
    int get_frame_to_swap = -1;

    while (get_frame_to_swap == -1) {
        int index = frame_table.sec_chance_index;

        // Verifica se o frame atual não foi acessado recentemente
        if (frames[index].accessed == 0) {
            get_frame_to_swap = index;  // Define o frame para ser substituído
        } else {
            frames[index].accessed = 0;  // Reseta a flag de acesso para 0
        }

        frame_table.sec_chance_index = (index + 1) % frame_table.nframes;  // Avança para o próximo frame na tabela
    }

    return get_frame_to_swap;  // Retorna o índice do frame a ser substituído
}


/*void swap_out_page(int frame_no) {
    //gambis: I do not know why I have to set PROT_NONE to all pages
    //when I am swapping the first one. Must investigate
    if(frame_no == 0) {
        for(int i = 0; i < frame_table.nframes; i++) {
            Page *page = frame_table.frames[i].page;
            mmu_chprot(frame_table.frames[i].pid, (void*)page->vaddr, PROT_NONE);
        }
    }

    FrameNode *frame = &frame_table.frames[frame_no];
    Page *removed_page = frame->page;
    removed_page->isvalid = 0;
    mmu_nonresident(frame->pid, (void*)removed_page->vaddr); 
    
    if(removed_page->dirty == 1) {
        block_table.blocks[removed_page->block_number].used = 1;
        mmu_disk_write(frame_no, removed_page->block_number);
    }
}*/

void swap_out_page(int frame_no) {

    // If we are swapping out the first frame, set PROT_NONE to all pages
    // This is a specific requirement that needs further investigation
    if (frame_no == 0) {
        for (int i = 0; i < frame_table.nframes; i++) {
            Page *page = frame_table.frames[i].page;
            mmu_chprot(frame_table.frames[i].pid, (void*)page->vaddr, PROT_NONE);
        }
    }

    // Get the frame and the page to be removed
    FrameNode *frame = &frame_table.frames[frame_no];
    Page *removed_page = frame->page;
    removed_page->isvalid = 0;  // Mark the page as invalid
    mmu_nonresident(frame->pid, (void*)removed_page->vaddr); // Remove the page from the resident set

    // If the page is dirty, write it back to the disk
    if (removed_page->dirty == 1) {
        int block_no = removed_page->block_number;
        BlockNode *block = &block_table.blocks[block_no];
        block->used = 1;  // Mark the block as used
        mmu_disk_write(frame_no, block_no);  // Write the page to disk
    }
}


/*void pager_fault(pid_t pid, void *vaddr) {
    pthread_mutex_lock(&locker);
    PageTable *pt = find_page_table(pid); 
    vaddr = (void*)((intptr_t)vaddr - (intptr_t)vaddr % frame_table.page_size);
    Page *page = get_page(pt, (intptr_t)vaddr); 

    if(page->isvalid == 1) {
        mmu_chprot(pid, vaddr, PROT_READ | PROT_WRITE);
        frame_table.frames[page->frame_number].accessed = 1;
        page->dirty = 1;
    } else {
        int frame_no = get_new_frame();

        //there is no frames available
        if(frame_no == -1) {
            frame_no = second_chance();
            swap_out_page(frame_no);
        }

        FrameNode *frame = &frame_table.frames[frame_no];
        frame->pid = pid;
        frame->page = page;
        frame->accessed = 1;

        page->isvalid = 1;
        page->frame_number = frame_no;
        page->dirty = 0;

        //this page was already swapped out from main memory
        if(block_table.blocks[page->block_number].used == 1) {
            mmu_disk_read(page->block_number, frame_no);
        } else {
            mmu_zero_fill(frame_no);
        }
        mmu_resident(pid, vaddr, frame_no, PROT_READ);
    }
    pthread_mutex_unlock(&locker);
}*/

void pager_fault(pid_t pid, void *vaddr) {

    pthread_mutex_lock(&locker);

    // Encontra a tabela de páginas do processo
    PageTable *page_t = find_page_table(pid);

    // Ajusta o endereço virtual para ser alinhado ao tamanho da página
    vaddr = (void*)((intptr_t)vaddr - (intptr_t)vaddr % frame_table.page_size);

    // Obtém a página correspondente ao endereço virtual
    Page *page = get_page(page_t, (intptr_t)vaddr);

    if (page->isvalid == 1) {
        // Se a página é válida, altera a proteção para permitir leitura e escrita
        mmu_chprot(pid, vaddr, PROT_READ | PROT_WRITE);
        frame_table.frames[page->frame_number].accessed = 1;
        page->dirty = 1;
    } else {
        int frame_no = get_new_frame();

        // Não há quadros de memória disponíveis
        if (frame_no == -1) {
            frame_no = second_chance();
            swap_out_page(frame_no);
        }

        FrameNode *frame = &frame_table.frames[frame_no];
        frame->pid = pid;
        frame->page = page;
        frame->accessed = 1;

        page->isvalid = 1;
        page->frame_number = frame_no;
        page->dirty = 0;

        // Verifica se a página foi previamente swapada para o disco
        if (block_table.blocks[page->block_number].used == 1) {
            mmu_disk_read(page->block_number, frame_no);
        } else {
            mmu_zero_fill(frame_no);
        }

        mmu_resident(pid, vaddr, frame_no, PROT_READ);
    }

    pthread_mutex_unlock(&locker);
}


/*int pager_syslog(pid_t pid, void *addr, size_t len) {

    pthread_mutex_lock(&locker);
    PageTable *pt = find_page_table(pid); 
    char *buf = (char*) malloc(len + 1);

    for (size_t i = 0, m = 0; i < len; i++) {
        Page *page = get_page(pt, (intptr_t)addr + i);

        //string out of process allocated space
        if(page == NULL) {
            pthread_mutex_unlock(&locker);
            return -1;
        }

        buf[m++] = pmem[page->frame_number * frame_table.page_size + i];
    }
    for(int i = 0; i < len; i++) { // len é o número de bytes a imprimir
        printf("%02x", (unsigned)buf[i]); // buf contém os dados a serem impressos
    }
    if(len > 0) printf("\n");
    pthread_mutex_unlock(&locker);
    return 0;
}*/

int pager_syslog(pid_t pid, void *addr, size_t len) {

    pthread_mutex_lock(&locker);

    PageTable *page_t = find_page_table(pid);

    // Verifica se o endereço está contido no espaço alocado pelo processo
    Page *start_page = get_page(page_t, (intptr_t)addr);
    Page *end_page = get_page(page_t, (intptr_t)addr + len - 1);

    if (start_page == NULL || end_page == NULL) {
        pthread_mutex_unlock(&locker);
        return -1;
    }

    // Aloca o buffer para armazenar os bytes
    char *buf = (char*)malloc(len + 1);

    for (size_t i = 0; i < len; i++) {
        Page *page = get_page(page_t, (intptr_t)addr + i);

        // Verifica se a página está válida
        if (page->isvalid != 1) {
            pthread_mutex_unlock(&locker);
            return -1;
        }

        // Copia o byte da memória física para o buffer
        buf[i] = pmem[page->frame_number * frame_table.page_size + ((intptr_t)addr + i) % frame_table.page_size];
    }

    // Imprime os bytes em formato hexadecimal
    for (size_t i = 0; i < len; i++) {
        printf("%02x", (unsigned)buf[i]);
    }
    if (len > 0) {
        printf("\n");
    }

    pthread_mutex_unlock(&locker);
    return 0;
}


/*void pager_destroy(pid_t pid) {
    pthread_mutex_lock(&locker);
    PageTable *pt = find_page_table(pid); 

    while(!dlist_empty(pt->pages)) {
        Page *page = dlist_pop_right(pt->pages);
        block_table.blocks[page->block_number].page = NULL;
        if(page->isvalid == 1) {
            frame_table.frames[page->frame_number].pid = -1;
        }
    }
    dlist_destroy(pt->pages, NULL);
    pthread_mutex_unlock(&locker);
}*/

void pager_destroy(pid_t pid) {

    pthread_mutex_lock(&locker);  // Bloqueia o acesso simultâneo à função

    PageTable *page_t = find_page_table(pid); // Encontra a tabela de páginas do processo

    while (!dlist_empty(page_t->pages)) {  // Enquanto a lista de páginas não estiver vazia
        Page *page = dlist_pop_right(page_t->pages);  // Remove a página do lado direito da lista

        if (page->block_number >= 0) {
            // Se a página estiver associada a um bloco no disco, define a referência do bloco como NULL
            block_table.blocks[page->block_number].page = NULL;
        }

        if (page->isvalid == 1) {
            // Se a página estiver em um quadro válido da memória física, remove a referência ao processo
            frame_table.frames[page->frame_number].pid = -1;
        }

        free(page);  // Libera a memória alocada para a página
    }

    dlist_destroy(page_t->pages, NULL);  // Destroi a lista de páginas do processo

    pthread_mutex_unlock(&locker);  // Libera o acesso à função
}


/////////////////Auxiliar functions ////////////////////////////////
/*int get_new_frame() {
    for(int i = 0; i < frame_table.nframes; i++) {
        if(frame_table.frames[i].pid == -1) return i;
    }
    return -1;
}

int get_new_block() {
    for(int i = 0; i < block_table.nblocks; i++) {
        if(block_table.blocks[i].page == NULL) return i;
    }
    return -1;
}

PageTable* find_page_table(pid_t pid) {
    for(int i = 0; i < page_tables->count; i++) {
        PageTable *pt = dlist_get_index(page_tables, i);
        if(pt->pid == pid) return pt;
    }
    printf("error in find_page_table: Pid not found\n");
    exit(-1);
}

Page* get_page(PageTable *pt, intptr_t vaddr) {
    for(int i=0; i < pt->pages->count; i++) {
        Page *page = dlist_get_index(pt->pages, i);
        if(vaddr >= page->vaddr && vaddr < (page->vaddr + frame_table.page_size)) return page;
    }
    return NULL;
}*/

/////////////////////// List functions //////////////////////////////
/*struct dlist *dlist_create(void) {
    struct dlist *dl = malloc(sizeof(struct dlist));
    assert(dl);
    dl->head = NULL;
    dl->tail = NULL;
    dl->count = 0;
    return dl;
}*/

/*void dlist_destroy(struct dlist *dl, dlist_data_func cb) {
    while(!dlist_empty(dl)) {
        void *data = dlist_pop_right(dl);
        if(cb) cb(data);
    }
    free(dl);
}*/

/*void *dlist_pop_right(struct dlist *dl) {
    if(dlist_empty(dl)) return NULL;

    void *data;
    struct dnode *node;

    node = dl->tail;

    dl->tail = node->prev;
    if(dl->tail == NULL) dl->head = NULL;
    if(node->prev) node->prev->next = NULL;

    data = node->data;
    free(node);

    dl->count--;
    assert(dl->count >= 0);

    return data;
}*/

/*void *dlist_push_right(struct dlist *dl, void *data) {
    struct dnode *node = malloc(sizeof(struct dnode));
    assert(node);

    node->data = data;
    node->prev = dl->tail;
    node->next = NULL;

    if(dl->tail) dl->tail->next = node;
    dl->tail = node;

    if(dl->head == NULL) dl->head = node;

    dl->count++;

    return data;
}*/

/*int dlist_empty(struct dlist *dl) {
    int ret;
    if(dl->head == NULL) {
        assert(dl->tail == NULL);
        assert(dl->count == 0);
        ret = 1;
    } else {
        assert(dl->tail != NULL);
        assert(dl->count > 0);
        ret = 0;
    }
    return ret;
}*/

/*void * dlist_get_index(const struct dlist *dl, int idx) {
    struct dnode *curr;
    if(idx >= 0) {
        curr = dl->head;
        while(curr && idx--) curr = curr->next;
    } else {
        curr = dl->tail;
        while(curr && ++idx) curr = curr->prev;
    }
    if(!curr) return NULL;
    return curr->data;
}*/