#include "pager.h"

#include <sys/mman.h>

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "mmu.h"

//Replicando estrutura de Dlist fornecida no arquivo TP1
//Todos os direitos reservados

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

typedef void (*dlist_data_func)(void *data);
typedef int (*dlist_cmp_func)(const void *e1, const void *e2, void *userdata); 

struct dlist *dlist_create(void);
void dlist_destroy(struct dlist *dl, dlist_data_func);
void *dlist_pop_left(struct dlist *dl);
void *dlist_pop_right(struct dlist *dl);
void *dlist_push_right(struct dlist *dl, void *data);
void *dlist_find_remove(struct dlist *dl, void *data, dlist_cmp_func cmp, void *userdata);
int dlist_empty(struct dlist *dl);
void * dlist_get_index(const struct dlist *dl, int idx);
void dlist_set_index(struct dlist *dl, int idx, void *data);


struct dlist *dlist_create(void) 
{
	struct dlist *dl = malloc(sizeof(struct dlist));
	assert(dl);
	dl->head = NULL;
	dl->tail = NULL;
	dl->count = 0;
	return dl;
} 

void dlist_destroy(struct dlist *dl, dlist_data_func cb) 
{
	while(!dlist_empty(dl)) {
		void *data = dlist_pop_left(dl);
		if(cb) cb(data);
	}
	free(dl);
} 

void *dlist_pop_left(struct dlist *dl) 
{
	void *data;
	struct dnode *node;

	if(dlist_empty(dl)) return NULL;

	node = dl->head;

	dl->head = node->next;
	if(dl->head == NULL) dl->tail = NULL;
	if(node->next) node->next->prev = NULL;

	data = node->data;
	free(node);

	dl->count--;
	assert(dl->count >= 0);
	return data;
} 

void *dlist_pop_right(struct dlist *dl) 
{
	void *data;
	struct dnode *node;

	if(dlist_empty(dl)) return NULL;

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

void *dlist_push_right(struct dlist *dl, void *data) 
{
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

void *dlist_find_remove(struct dlist *dl, void *data, 
		dlist_cmp_func cmp, void *user_data)
{
	struct dnode *curr;
	for(curr = dl->head; curr; curr = curr->next) {
		if(!curr->data) continue;
		if(cmp(curr->data, data, user_data)) continue;
		void *ptr = curr->data;
		if(dl->head == curr) dl->head = curr->next;
		if(dl->tail == curr) dl->tail = curr->prev;
		if(curr->prev) curr->prev->next = curr->next;
		if(curr->next) curr->next->prev = curr->prev;
		dl->count--;
		free(curr);
		return ptr;
	}
	return NULL;
} 

int dlist_empty(struct dlist *dl) 
{
	if(dl->head == NULL) {
		assert(dl->tail == NULL);
		assert(dl->count == 0);
		return 1;
	} else {
		assert(dl->tail != NULL);
		assert(dl->count > 0);
		return 0;
	}
} 

void * dlist_get_index(const struct dlist *dl, int idx) 
{
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

void dlist_set_index(struct dlist *dl, int idx, void *data) 
{
	struct dnode *curr;
	if(idx >= 0) {
		curr = dl->head;
		while(curr && idx--) curr = curr->next;
	} else {
		curr = dl->tail;
		while(curr && ++idx) curr = curr->prev;
	}
	if(!curr) return;
	curr->data = data;
} 

// fim das implementações da lista 

// estruturas do paginador

typedef struct Pagina {
    int BitValidacao;
    int NumeroQuadro;
    int NumeroBloco;
    int BitModificacao;
    intptr_t EnderecoVirtual;
} Pagina_t;

typedef struct TabelaPaginacao {
    pid_t pid;
    struct dlist *Paginas;
} TabelaPaginacao_t;

typedef struct {
    pid_t pid;
    Pagina_t *pagina;
    int acessado; 
} QuadroListaNode;

typedef struct {
    int utilizado; 
    Pagina_t *pagina;
} BlocoListaNode;

typedef struct TabelaBlocos{
    int numeroBlocos;
    BlocoListaNode *blocos;
} TabelaBlocos_t;

TabelaBlocos_t tabelaBlocos;

typedef struct TabelaQuadros{
    int numeroQuadros;
    int tamanhoPagina;
    int indiceParaSegundaChance;
    QuadroListaNode *quadros;
} TabelaQuadros_t;

TabelaQuadros_t tabelaQuadros;

struct dlist *tabelaPaginacao;

//funcoes auxiliares

//TabelaPaginacao_t* getTabelaPaginacao(pid_t pid);
TabelaPaginacao_t* getTabelaPaginacao(pid_t pid) {

    for(int i = 0; i < tabelaPaginacao->count; i++) {
        TabelaPaginacao_t
     *pt = dlist_get_index(tabelaPaginacao, i);
        if(pt->pid == pid) return pt;
    }
    exit(-1);
}
//Pagina_t* getPagina(TabelaPaginacao_t *pt, intptr_t EnderecoVirtual);
Pagina_t* getPagina(TabelaPaginacao_t *pt, intptr_t EnderecoVirtual) {
    
    for(int i=0; i < pt->Paginas->count; i++) {
        Pagina_t *pagina = dlist_get_index(pt->Paginas, i);
        if(EnderecoVirtual >= pagina->EnderecoVirtual && EnderecoVirtual < (pagina->EnderecoVirtual + tabelaQuadros.tamanhoPagina)) return pagina;
    }
    return NULL;
}

// definindo o mutex
pthread_mutex_t mutex;

//funcoes do paginador de memoria


/* `pager_init` is called by the memory management infrastructure to
 * initialize the pager.  `nframes` and `nblocks` are the number of
 * physical memory quadros available and the number of blocks for
 * backing store, respectively. */
void pager_init(int numeroQuadros, int numeroBlocos) {

    // Bloqueia o mutex para acesso exclusivo às estruturas de dados
    pthread_mutex_lock(&mutex);
    // Define o número de quadros físicos disponíveis
    tabelaQuadros.numeroQuadros = numeroQuadros;
    // Obtém o tamanho da página em bytes do sistema
    tabelaQuadros.tamanhoPagina = sysconf(_SC_PAGESIZE);
    // Inicializa o índice do algoritmo de substituição de página
    tabelaQuadros.indiceParaSegundaChance = 0;
    // Aloca memória para o array de quadros
    tabelaQuadros.quadros = (QuadroListaNode*)malloc(numeroQuadros * sizeof(QuadroListaNode));

    //setando todos os quadros como -1
    // Inicializa todos os quadros com valor -1 para indicar que estão vazios
    for (int i = 0; i < numeroQuadros; i++) {
        tabelaQuadros.quadros[i].pid = -1;
    }
    // Define o número de blocos disponíveis na memória secundária
    tabelaBlocos.numeroBlocos = numeroBlocos;
    // Aloca memória para o array de blocos
    tabelaBlocos.blocos = (BlocoListaNode*)malloc(numeroBlocos * sizeof(BlocoListaNode));

    //setando todos os blocos como não utilizados 
    // Inicializa todos os blocos com valor 0 para indicar que não estão sendo utilizados
    for (int i = 0; i < numeroBlocos; i++) {
        tabelaBlocos.blocos[i].utilizado = 0;
    }

    tabelaPaginacao = dlist_create(); // Cria a lista para armazenar as tabelas de páginas

    pthread_mutex_unlock(&mutex); // Desbloqueia o mutex para permitir acesso concorrente às estruturas de dados
}


/* `pager_create` should initialize any resources the pager needs to
 * manage memory for a new process `pid`. */
void pager_create(pid_t pid) {

    pthread_mutex_lock(&mutex);// Bloqueia o mutex para acesso exclusivo às estruturas de dados
    // Criar uma nova estrutura TabelaPaginacao_t

    TabelaPaginacao_t
 *page_t = (TabelaPaginacao_t
*) malloc(sizeof(TabelaPaginacao_t
));
    page_t->pid = pid;
    page_t->Paginas = dlist_create();
    // Adicionar a nova TabelaPaginacao_t à lista de tabelaPaginacao
    dlist_push_right(tabelaPaginacao, page_t);
    pthread_mutex_unlock(&mutex);// Desbloqueia o mutex para permitir acesso concorrente às estruturas de dados

}


/* `pager_extend` allocates a new pagina of memory to process `pid`
 * and returns a pointer to that memory in the process's address
 * space.  `pager_extend` need not zero memory or install mappings
 * in the infrastructure until the application actually accesses the
 * pagina (which will trigger a call to `pager_fault`).
 * `pager_extend` should return NULL is there are no disk blocks to
 * use as backing storage. */
void *pager_extend(pid_t pid) {

    pthread_mutex_lock(&mutex); // Adquire o bloqueio do mutex para garantir exclusão mútua
    int sucesso = 0;
    int novoBloco;
    // Obtém um bloco disponível na tabela de blocos
    for(int i = 0; i < tabelaBlocos.numeroBlocos; i++) {
        if(tabelaBlocos.blocos[i].pagina == NULL) {
            novoBloco = i;
            sucesso = 1;
            break;
        }
    }
    if (sucesso == 0) {
        novoBloco = -1;
    }

    if (novoBloco == -1) { // Não há mais blocos disponíveis
        pthread_mutex_unlock(&mutex); // Libera o bloqueio do mutex antes de retornar
        return NULL; // Retorna NULL para indicar falha na alocação
    }

    TabelaPaginacao_t *page_t = getTabelaPaginacao(pid); // Encontra a tabela de páginas do processo

    Pagina_t *pagina = (Pagina_t*)malloc(sizeof(Pagina_t)); // Aloca memória para a nova página

    pagina->BitValidacao = 0;
    pagina->EnderecoVirtual = UVM_BASEADDR + page_t->Paginas->count * tabelaQuadros.tamanhoPagina;
    pagina->NumeroBloco = novoBloco;

    dlist_push_right(page_t->Paginas, pagina); // Insere a nova página na lista de páginas da tabela de páginas

    tabelaBlocos.blocos[novoBloco].pagina = pagina; // Atualiza a tabela de blocos com a referência à nova página

    pthread_mutex_unlock(&mutex); // Libera o bloqueio do mutex antes de retornar
    return (void*)pagina->EnderecoVirtual; // Retorna o endereço virtual da nova página
}



void trocarPagina(int numeroQuadro) {
    if (numeroQuadro == 0) {
        for (int i = 0; i < tabelaQuadros.numeroQuadros; i++) {
            Pagina_t *pagina = tabelaQuadros.quadros[i].pagina;
            mmu_chprot(tabelaQuadros.quadros[i].pid, (void*)pagina->EnderecoVirtual, PROT_NONE);
        }
    }

    // Get the frame and the pagina to be removed
    QuadroListaNode *frame = &tabelaQuadros.quadros[numeroQuadro];
    Pagina_t *removed_page = frame->pagina;
    removed_page->BitValidacao = 0;  // Mark the pagina as invalid
    mmu_nonresident(frame->pid, (void*)removed_page->EnderecoVirtual); // Remove the pagina from the resident set

    // If the pagina is BitModificacao, write it back to the disk
    if (removed_page->BitModificacao == 1) {
        int numeroBloco = removed_page->NumeroBloco;
        BlocoListaNode *block = &tabelaBlocos.blocos[numeroBloco];
        block->utilizado = 1;  // Mark the block as utilizado
        mmu_disk_write(numeroQuadro, numeroBloco);  // Write the pagina to disk
    }
}

/* `pager_fault` is called when process `pid` receives
 * a segmentation fault at address `addr`.  `pager_fault` is only
 * called for addresses previously returned with `pager_extend`.  If
 * free memory quadros exist, `pager_fault` should use the
 * lowest-numbered frame to service the pagina fault.  If no free
 * memory quadros exist, `pager_fault` should use the second-chance
 * (also known as clock) algorithm to choose which frame to pagina to
 * disk.  Your second-chance algorithm should treat read and write
 * accesses the same (i.e., do not prioritize either).  As the
 * memory management infrastructure does not maintain pagina access
 * and writing information, your pager must track this information
 * to implement the second-chance algorithm. */
void pager_fault(pid_t pid, void *EnderecoVirtual) {

    pthread_mutex_lock(&mutex);

    // Encontra a tabela de páginas do processo
    TabelaPaginacao_t *page_t = getTabelaPaginacao(pid);

    // Ajusta o endereço virtual para ser alinhado ao tamanho da página
    EnderecoVirtual = (void*)((intptr_t)EnderecoVirtual - (intptr_t)EnderecoVirtual % tabelaQuadros.tamanhoPagina);

    // Obtém a página correspondente ao endereço virtual
    Pagina_t *pagina = getPagina(page_t, (intptr_t)EnderecoVirtual);

    if (pagina->BitValidacao == 1) {
        // Se a página é válida, altera a proteção para permitir leitura e escrita
        mmu_chprot(pid, EnderecoVirtual, PROT_READ | PROT_WRITE);
        tabelaQuadros.quadros[pagina->NumeroQuadro].acessado = 1;
        pagina->BitModificacao = 1;
    } 
    else{
        int sucesso = 0;
        int numeroQuadro;
        for(int i = 0; i < tabelaQuadros.numeroQuadros; i++) {
            if(tabelaQuadros.quadros[i].pid == -1) {
                numeroQuadro = i;
                sucesso = 1;
                break;
            }
        }
        if (sucesso == 0) {
            numeroQuadro = -1;
        }

        // Se não houver quadro disponivel, executa a segunda chance
        if (numeroQuadro == -1) {
            QuadroListaNode *quadros = tabelaQuadros.quadros;
            while (numeroQuadro == -1) {
                int index = tabelaQuadros.indiceParaSegundaChance;

                // Verifica se o frame atual não foi acessado recentemente
                if (quadros[index].acessado == 0) {
                    numeroQuadro = index;  // Define o frame para ser substituído
                } 
                else {
                    quadros[index].acessado = 0;  // Reseta a flag de acesso para 0
                }

                tabelaQuadros.indiceParaSegundaChance = (index + 1) % tabelaQuadros.numeroQuadros;  // Avança para o próximo frame na tabela
            }
            trocarPagina(numeroQuadro);
        }

        QuadroListaNode *frame = &tabelaQuadros.quadros[numeroQuadro];
        frame->pid = pid;
        frame->pagina = pagina;
        frame->acessado = 1;

        pagina->BitValidacao = 1;
        pagina->NumeroQuadro = numeroQuadro;
        pagina->BitModificacao = 0;

        // Verifica se a página foi previamente swapada para o disco
        if (tabelaBlocos.blocos[pagina->NumeroBloco].utilizado == 1) {
            mmu_disk_read(pagina->NumeroBloco, numeroQuadro);
        } 
        else {
            mmu_zero_fill(numeroQuadro);
        }

        mmu_resident(pid, EnderecoVirtual, numeroQuadro, PROT_READ);
    }

    pthread_mutex_unlock(&mutex);
}


/* `pager_syslog prints a message made of `len` bytes following
 * `addr` in the address space of process `pid`.  `pager_syslog`
 * should behave as if making read accesses to the process's memory
 * (zeroing and swapping in pages from disk if necessary).  If the
 * processes tries to syslog a memory region it has not allocated,
 * then `pager_syslog` should return -1 and set errno to EINVAL; if
 * the syslog succeeds, it should return 0. */
int pager_syslog(pid_t pid, void *addr, size_t len) {

    pthread_mutex_lock(&mutex);

    TabelaPaginacao_t
 *page_t = getTabelaPaginacao(pid);

    // Verifica se o endereço está contido no espaço alocado pelo processo
    Pagina_t *start_page = getPagina(page_t, (intptr_t)addr);
    Pagina_t *end_page = getPagina(page_t, (intptr_t)addr + len - 1);

    if (start_page == NULL || end_page == NULL) {
        pthread_mutex_unlock(&mutex);
        return -1;
    }

    // Aloca o buffer para armazenar os bytes
    char *buf = (char*)malloc(len + 1);

    for (size_t i = 0; i < len; i++) {
        Pagina_t *pagina = getPagina(page_t, (intptr_t)addr + i);

        // Verifica se a página está válida
        if (pagina->BitValidacao != 1) {
            pthread_mutex_unlock(&mutex);
            return -1;
        }

        // Copia o byte da memória física para o buffer
        buf[i] = pmem[pagina->NumeroQuadro * tabelaQuadros.tamanhoPagina + ((intptr_t)addr + i) % tabelaQuadros.tamanhoPagina];
    }

    // Imprime os bytes em formato hexadecimal
    for (size_t i = 0; i < len; i++) {
        printf("%02x", (unsigned)buf[i]);
    }
    if (len > 0) {
        printf("\n");
    }

    pthread_mutex_unlock(&mutex);
    return 0;
}


/* `pager_destroy` is called when the process is already dead.  It
 * should free all resources process `pid` allocated (memory quadros
 * and disk blocks).  `pager_destroy` should not call any of the MMU
 * functions. */
void pager_destroy(pid_t pid) {

    pthread_mutex_lock(&mutex);  // Bloqueia o acesso simultâneo à função

    TabelaPaginacao_t
 *page_t = getTabelaPaginacao(pid); // Encontra a tabela de páginas do processo

    while (!dlist_empty(page_t->Paginas)) {  // Enquanto a lista de páginas não estiver vazia
        Pagina_t *pagina = dlist_pop_right(page_t->Paginas);  // Remove a página do lado direito da lista

        if (pagina->NumeroBloco >= 0) {
            // Se a página estiver associada a um bloco no disco, define a referência do bloco como NULL
            tabelaBlocos.blocos[pagina->NumeroBloco].pagina = NULL;
        }

        if (pagina->BitValidacao == 1) {
            // Se a página estiver em um quadro válido da memória física, remove a referência ao processo
            tabelaQuadros.quadros[pagina->NumeroQuadro].pid = -1;
        }

        free(pagina);  // Libera a memória alocada para a página
    }

    dlist_destroy(page_t->Paginas, NULL);  // Destroi a lista de páginas do processo

    pthread_mutex_unlock(&mutex);  // Libera o acesso à função
}
