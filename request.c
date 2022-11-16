#include "io_helper.h"
#include "request.h"

#define MAXBUF (8192)


//
//	TODO: add code to create and manage the buffer
//
int created=0;

typedef struct node
{
	int fd;
	char* fname;
	int fsize;
	struct node* next;
}node;

typedef struct queue
{
	struct node* head;
	struct node* tail;
}queue;

node* createnode(int fd,char* fname,int fsize)
{
	node* n = (node*)malloc(sizeof(node));
	n->fd = fd;
	n->fname = fname;
	n->fsize = fsize;
	n->next = NULL;
	return n;
}

int qempty(queue* q)
{
	if(q->head == NULL)
	{
		return 1;
	}
	return 0;
}

void enqueue(queue* q,node* n)
{
	if(q->head == NULL)
	{
			q->head = n;
			q->tail = n;
	}
	else
	{
		q->tail->next = n;
		q->tail = q->tail->next;
	}
}

node* dequeue(queue* q)
{
	if(qempty(q))
	{
		return NULL;
	}
	node* tmp = q->head;
	q->head = q->head->next;
	tmp->next = NULL;
	return tmp;
}
queue* qcreate()
{
	queue* q = (queue*)malloc(sizeof(queue));
	q->head = NULL;
	q->tail = NULL;
	printf("queue created \n");
	return q;
}

queue* schedul(queue* que,node* new,int choice)
{
	if(choice == 0) // FIFO
	{

		//pthread_cond_wait(&c_cv)
		enqueue(que,new);
	}
	else //if(choice == 1) // SFF
	{
		queue* tmp = que;
		queue* ptr = NULL;
		if(tmp->head == NULL || new->fsize < tmp->head->fsize) // if queue is empty or if "node" is lower size then the head
		{
			new->next = tmp->head;
			tmp->head = new;
		}
		else // queue has one or more elements.
		{
			ptr = que;
			while(ptr->head->next != NULL && (new->fsize > ptr->head->next->fsize))
			{
				ptr->head = ptr->head->next;
			}
			new->next = ptr->head->next;
			ptr->head->next = new;
		}
	}
	return que;
}

queue* que = NULL; // creating a queue;

pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mut1 = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t p_cv = PTHREAD_COND_INITIALIZER;
pthread_cond_t c_cv = PTHREAD_COND_INITIALIZER;
//
// Sends out HTTP response in case of errors
//
void request_error(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg) {
    char buf[MAXBUF], body[MAXBUF];

    // Create the body of error message first (have to know its length for header)
    sprintf(body, ""
	    "<!doctype html>\r\n"
	    "<head>\r\n"
	    "  <title>OSTEP WebServer Error</title>\r\n"
	    "</head>\r\n"
	    "<body>\r\n"
	    "  <h2>%s: %s</h2>\r\n"
	    "  <p>%s: %s</p>\r\n"
	    "</body>\r\n"
	    "</html>\r\n", errnum, shortmsg, longmsg, cause);

    // Write out the header information for this response
    sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
    write_or_die(fd, buf, strlen(buf));

    sprintf(buf, "Content-Type: text/html\r\n");
    write_or_die(fd, buf, strlen(buf));

    sprintf(buf, "Content-Length: %lu\r\n\r\n", strlen(body));
    write_or_die(fd, buf, strlen(buf));

    // Write out the body last
    write_or_die(fd, body, strlen(body));

    // close the socket connection
    close_or_die(fd);
}

//
// Reads and discards everything up to an empty text line
//
void request_read_headers(int fd) {
    char buf[MAXBUF];

    readline_or_die(fd, buf, MAXBUF);
    while (strcmp(buf, "\r\n")) {
		readline_or_die(fd, buf, MAXBUF);
    }
    return;
}

//
// Return 1 if static, 0 if dynamic content (executable file)
// Calculates filename (and cgiargs, for dynamic) from uri
//
int request_parse_uri(char *uri, char *filename, char *cgiargs) {
    char *ptr;

    if (!strstr(uri, "cgi")) {
	// static
	strcpy(cgiargs, "");
	sprintf(filename, ".%s", uri);
	if (uri[strlen(uri)-1] == '/') {
	    strcat(filename, "index.html");
	}
	return 1;
    } else {
	// dynamic
	ptr = index(uri, '?');
	if (ptr) {
	    strcpy(cgiargs, ptr+1);
	    *ptr = '\0';
	} else {
	    strcpy(cgiargs, "");
	}
	sprintf(filename, ".%s", uri);
	return 0;
    }
}

//
// Fills in the filetype given the filename
//
void request_get_filetype(char *filename, char *filetype) {
    if (strstr(filename, ".html"))
		strcpy(filetype, "text/html");
    else if (strstr(filename, ".gif"))
		strcpy(filetype, "image/gif");
    else if (strstr(filename, ".jpg"))
		strcpy(filetype, "image/jpeg");
    else
		strcpy(filetype, "text/plain");
}

//
// Handles requests for static content
//
void request_serve_static(int fd, char *filename, int filesize) {
    int srcfd;
    char *srcp, filetype[MAXBUF], buf[MAXBUF];

    request_get_filetype(filename, filetype);
    srcfd = open_or_die(filename, O_RDONLY, 0);

    // Rather than call read() to read the file into memory,
    // which would require that we allocate a buffer, we memory-map the file
    srcp = mmap_or_die(0, filesize, PROT_READ, MAP_PRIVATE, srcfd, 0);
    close_or_die(srcfd);

    // put together response
    sprintf(buf, ""
	    "HTTP/1.0 200 OK\r\n"
	    "Server: OSTEP WebServer\r\n"
	    "Content-Length: %d\r\n"
	    "Content-Type: %s\r\n\r\n",
	    filesize, filetype);

    write_or_die(fd, buf, strlen(buf));

    //  Writes out to the client socket the memory-mapped file
    write_or_die(fd, srcp, filesize);
    munmap_or_die(srcp, filesize);
}

//
// Fetches the requests from the buffer and handles them (thread locic)
//
void* thread_request_serve_static(void* arg)
{
	node* n = NULL;
	pthread_mutex_lock(&mut1);
	if(created == 0)
	{
		que = qcreate();
		created = 1;
	}
	pthread_mutex_unlock(&mut1);
	while(1)
	{
		//printf("First_print after while inside a thread\n");
		pthread_mutex_lock(&mut);
		if(!qempty(que))
		{
			pthread_cond_wait(&p_cv,&mut);
			//printf("Before Dequeue..............\n");
			//printqueue(que);
			n = dequeue(que);
			//printf("After Dequeue................\n");
			//printqueue(que);
			//printf("Dequeued a file\n");
			//pthread_cond_signal(&c_cv);
		}
			pthread_mutex_unlock(&mut);
	if(n != NULL)
	{
		request_serve_static(n->fd,n->fname,n->fsize);
		printf("size of %s is %d\n",n->fname,n->fsize);
	}
					//printf("After unlock\n");
	}
	return NULL;
	// TODO: write code to actualy respond to HTTP requests
}

//
// Initial handling of the request
//
void request_handle(int fd) {
    int is_static;
    struct stat sbuf;
    char buf[MAXBUF], method[MAXBUF], uri[MAXBUF], version[MAXBUF];
    char filename[MAXBUF], cgiargs[MAXBUF];

	// get the request type, file path and HTTP version
    readline_or_die(fd, buf, MAXBUF);
    sscanf(buf, "%s %s %s", method, uri, version);
    printf("method:%s uri:%s version:%s\n", method, uri, version);

	// verify if the request type is GET is not
    if (strcasecmp(method, "GET")) {
		request_error(fd, method, "501", "Not Implemented", "server does not implement this method");
		return;
    }
    request_read_headers(fd);

	// check requested content type (static/dynamic)
    is_static = request_parse_uri(uri, filename, cgiargs);

	// get some data regarding the requested file, also check if requested file is present on server
    if (stat(filename, &sbuf) < 0) {
		request_error(fd, filename, "404", "Not found", "server could not find this file");
		return;
    }

	// verify if requested content is static
    if (is_static) {
		if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode)) {
			request_error(fd, filename, "403", "Forbidden", "server could not read this file");
			return;
		}
		//producer code;
				pthread_mutex_lock(&mut);
		node* new = createnode(fd,filename,sbuf.st_size);
		//printf("After creating a node\n");
		//printf("Before producer code\n");
		que = schedul(que,new,scheduling_algo); // scheduling....................
		//printf("Enqueued\n");

		//printf("after request serve\n");
		pthread_cond_signal(&p_cv);
		pthread_mutex_unlock(&mut);
		// TODO: write code to add HTTP requests in the buffer based on the scheduling policy

    } else {
		request_error(fd, filename, "501", "Not Implemented", "server does not serve dynamic content request");
    }
}
