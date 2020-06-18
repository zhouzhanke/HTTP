#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

typedef struct sockaddr SA;
FILE *log_file;
char *base_dir;
char *request_file;
static int is_interrupted   = 0;

#define EXIT_ON_FAIL(val1, val2, msg, exit_code) \
    if ((val1) == (val2)) { \
    perror(msg); \
    exit(exit_code); \
    }


// Structure to hold meta data
typedef struct meta_data{
    pthread_mutex_t mutex;  /* Lock for the data structure */
    
    int total_request;
    int successful_request;
    int forbidden_request;
    int not_found_request;
    int others;
} meta; 

meta *header;

void log_to_file(char * msg) {
    fprintf(log_file, "%s", msg);
    perror(msg);
}

void respond_msg(int code, char * msg) {
    // lock
    if (pthread_mutex_lock(&(header->mutex)) != 0)
        log_to_file("Error: fail to lock mutex\n");
    
    switch (code) {
    case 200:
        header->successful_request++;
        fprintf(log_file, "Done: 200 %s\n", request_file);
        // print in another location
        break;
        
    case 403:
        header->forbidden_request++;
        fprintf(log_file, "Done: 403 %s\n", request_file);
        log_to_file(msg);
        fprintf(stdout, "HTTP/1.1 403 Forbidden\r\n"
                        "Content-Length: %ld\r\n"
                        "\r\n"
                        "<h1>403 Forbidden</h1>\r\n", strlen("<h1>403 Forbidden</h1>"));
        break;
        
    case 404:
        header->not_found_request++;
        fprintf(log_file, "Done: 404 %s\n", request_file);
        log_to_file(msg);
        fprintf(stdout, "HTTP/1.1 404 Not Found\r\n"
                        "Content-Length: %ld\r\n"
                        "\r\n"
                        "<h1>404 Not Found</h1>\r\n", strlen("<h1>404 Not Found</h1>"));
        break;
        
    case 500:
        header->others++;
        if (request_file == NULL)
            fprintf(log_file, "Done: 500 %s/<path not resolved yet>\n", base_dir);
        else {
            fprintf(log_file, "Done: 500 %s\n", request_file);
        }
        log_to_file(msg);
        fprintf(stdout, "HTTP/1.1 500 Internal Server Error\r\n"
                        "Content-Length: %ld\r\n"
                        "\r\n"
                        "<h1>500 Internal Server Error</h1>\r\n", strlen("<h1>500 Internal Server Error</h1>"));
        break;
        
    case -1:
        log_to_file(msg);
        break;
        
    default:
        break;
    }
    // unlock
    if (pthread_mutex_unlock(&(header->mutex)) != 0)
        log_to_file("Error: fail to unlock mutex");
}

// Returns nonzero iff line is a string containing only whitespace (or is empty)
int isBlank (char * line) {
    char * ch;
    int is_blank = 0;
    
    // Iterate through each character.
    for (ch = line; *ch != '\0'; ++ch) {
        if (!isspace(*ch)) {
            // Found a non-whitespace character.
            is_blank = -1;
            break;
        }
    }
    
    return is_blank;
}

/* Function: break_up_command
 * Breaks up a command (cmd) by the delimiter provided.
 * Returns array of strings, with last entry being NULL.  Suitable for execv*()
 * Returns NULL on error.
 * Note: cmd is modified by this function.
 */
char **break_up_command(char *cmd, char *delimeter) {
    int n_items, max_items;
    char **result;
    char *tmp;
    
    /* Make sure the delimiters are valid */
    if (delimeter == NULL)
        return NULL;
    
    /* Start with too large an array - max will be length of string */
    max_items = strlen(cmd);
    result = (char **) malloc(max_items * sizeof(char *));
    if (result == NULL)
        return NULL;
    
    /* Use strtok to split up cmd, storing each item in result array */
    n_items = 0;
    tmp = strtok(cmd, delimeter);
    while (tmp != NULL) {
        result[n_items] = tmp;
        n_items++;
        
        tmp = strtok(NULL, delimeter);
    }
    
    /* Make the last entry NULL */
    result[n_items] = NULL;
    
    /* Re-size to an appropriate size array */
    result = realloc(result, (n_items+1) * sizeof(char *));
    
    return result;
}

// check file type
mode_t file_check(const char *path)
{
    struct stat path_stat;
    stat(path, &path_stat);
    return path_stat.st_mode;
}

/* Function to set the is_interrupted flag.
 * This should be called when an interrupt signal is sent
 */
void sigint_received(int signum) {
    switch (signum) {
    case SIGINT:
        printf("Received SIGINT\n");
        is_interrupted = 1;
        break;
    default:
        break;
    }
}

/* Function: handle_client
 * Respond to a client.  Read a 4-byte unsigned integer from the client, 
 * double it, and send the result back.  This code does not check for 
 * overflow.
 * Function simply prints a notice and returns on an error.
 */
static void handle_client(int fd) {
    int status;
    
    /* create a new child, and exit on failure */
    int pid = fork();
    if (pid == -1) {
        respond_msg(500, "Error: child process creation failed\n");
    }
    
    // child job
    if (pid == 0) {
        dup2(fd, 0); // send stdin to fd
        dup2(fd, 1); // send stdout to fd
        
        // get command (1st line)
        char * cmd = NULL;
        size_t cmd_size = 0;
        
        if (getline(&cmd, &cmd_size, stdin) == -1) {
            respond_msg(500, "Error: fail to get command\n");
            exit(EXIT_FAILURE);
        }
        strtok(cmd, "\r\n");	// chop off end part
        
        // check rest of lines
        while (1) {
            char * other;
            size_t other_size = 0;
            
            if (getline(&other, &other_size, stdin) == -1)
                break;
            
            // check for last black line
            if (isBlank(other) == -1) {
                break;
            }
            // check other 
            if (strstr(other, ": ") == NULL) {
                respond_msg(500, "Error: invalid input format\n");
                exit(EXIT_FAILURE);
            }
        }
        
        // break up command
        char **cmd_part = break_up_command(cmd, " \t");
        if (cmd_part == NULL || strcmp(cmd_part[0], "GET") != 0 || strcmp(cmd_part[2], "HTTP/1.1") != 0) {
            respond_msg(500, "Error: invalid input format\n");
            exit(EXIT_FAILURE);
        }
        
        // operate the request
        // get file path
        request_file = malloc(strlen(base_dir)+strlen(cmd_part[1]));
        if(request_file != NULL){
            request_file[0] = '\0';   // ensures the memory is an empty string
            strcat(request_file, base_dir);
            strcat(request_file, cmd_part[1]);
        } else {
            respond_msg(500, "Error: fail to allocate memory to hold request file\n");
            exit(EXIT_FAILURE);
        }
        
        if (strcmp(cmd_part[1], "/status") == 0) {
            respond_msg(200, NULL);
            
            // lock
            if (pthread_mutex_lock(&(header->mutex)) != 0)
                log_to_file("Error: fail to lock mutex\n");
            
            FILE * status_file;
            status_file= fopen(request_file, "w");
            
            fprintf(status_file, "<h1>Status</h1>\r\n"
                                 "<p>Total Requests: %d<br />"
                                 "200: %d<br />403: %d<br />"
                                 "404: %d<br />500: %d"
                                 "</p>", header->total_request, header->successful_request,
                    header->forbidden_request, header->not_found_request, header->others);
            fclose(status_file);
            
            // unlock
            if (pthread_mutex_unlock(&(header->mutex)) != 0)
                log_to_file("Error: fail to unlock mutex");
        }
        
        // check if file exist
        if (access(request_file, F_OK) == -1) {
            respond_msg(404, "Error: request file not exist\n");
            exit(EXIT_FAILURE);
        }
        
        // check the type and read permission of the file
        mode_t file_stat = file_check(request_file);
        if (!S_ISREG(file_stat) || (file_stat & S_IRUSR) == 0) {
            respond_msg(403, "Error: request file is not a regular file or user has no read permission\n");
            exit(EXIT_FAILURE);
        }
        
        // open required file
        FILE *file = fopen(request_file, "r");
        char * buff;
        char * content = NULL;
        size_t buff_size = 0;
        while (1) {
            if (getline(&buff, &buff_size, file) == EOF)
                break;
            content = realloc(content, sizeof (content) + buff_size);
            strcat(content, buff);
        }
        if (strcmp(cmd_part[1], "/status") != 0) {
            respond_msg(200, NULL);
        }
        // lock
        if (pthread_mutex_lock(&(header->mutex)) != 0)
            log_to_file("Error: fail to lock mutex\n");
        
        fprintf(stdout, "HTTP/1.1 200 OK\r\n"
                        "Content-Length: %ld\r\n"
                        "\r\n"
                        "%s", strlen(content), content);
        
        // unlock
        if (pthread_mutex_unlock(&(header->mutex)) != 0)
            log_to_file("Error: fail to unlock mutex");
        
        // close pipe
        status = close(fd);
        if (status == -1) {
            respond_msg(500, "Error: fail to close pipe\n");
            exit(EXIT_FAILURE);
        }
        
        free(request_file);
        free(content);
        exit(EXIT_SUCCESS);
    }
}

int main(int argc, char **argv)
{
    int status;
    // check command line args
    if(argc != 4) {
        fprintf(stderr, "Usage: %s <base file> <port number> <log file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    // validate base directory
    if (!S_ISDIR(file_check(argv[1]))) {
        fprintf(stderr, "Error: base directory not valid\n");
        exit(EXIT_FAILURE);
    }
    base_dir = argv[1];
    
    // validate port number
    int port_num = atoi(argv[2]);
    if (port_num <= 0) {
        fprintf(stderr, "Error: fail to get port number\n");
    }
    
    // try open log file
    log_file = fopen(argv[3], "a");
    EXIT_ON_FAIL(log_file, NULL, "Error: fail to open log file\n", EXIT_FAILURE);
    
    // set up meta data for request
    void *allocated;
    pthread_mutexattr_t mutex_attrs;
    
    /* Allocate the memory.  Let's make it shared so all threads AND 
     * children (and childrens' threads) can access this
     */
    allocated = mmap(NULL, sizeof (meta), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    EXIT_ON_FAIL(allocated, NULL, "Error: fail to create meta data for request\n", EXIT_FAILURE);
    
    header = (meta *) allocated;
    header->total_request = 0;
    header->successful_request = 0;
    header->forbidden_request = 0;
    header->not_found_request = 0;
    header->others = 0;
    
    // set up mutex
    pthread_mutexattr_init(&mutex_attrs);
    pthread_mutexattr_setpshared(&mutex_attrs, PTHREAD_PROCESS_SHARED);
    if (pthread_mutex_init(&(header->mutex), &mutex_attrs) != 0) {
        munmap(allocated, sizeof (meta));
        fprintf(stderr, "Error: fail to set up mutex\n");
        exit(EXIT_FAILURE);
    }
    
    
    // Set up interrupt handler
    struct sigaction sigint_handler;
    
    sigint_handler.sa_handler = sigint_received;
    sigemptyset(&sigint_handler.sa_mask);
    sigint_handler.sa_flags = 0;
    
    if (sigaction(SIGINT, &sigint_handler, NULL) != 0) {
        fprintf(stderr, "Error: fail to detect signal SIGINT\n");
        exit(EXIT_FAILURE);
    }
    
    // set up socket
    int client_number = 1;
    int server_socket;
    
    struct sockaddr_in address, client_address;
    int client_address_size;
    
    /* Define an address that means port 7810 on all my network interfaces */
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port_num);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    
    /* Create and prepare the socket the server will listen for connections on
     * See 'man 2 socket', 'man 2 connect', and 'man 7 ip' for details 
     */
    
    /* Create a TCP socket */
    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EXIT_ON_FAIL(server_socket, -1, "Error: Failed to create socket\n", EXIT_FAILURE);
    fprintf(stderr, "socket created: %d\n", server_socket);
    
    /* Assign it the address defined above (all on port provided by user) */
    status = bind(server_socket, (SA*)&address, sizeof(address));
    EXIT_ON_FAIL(status, -1, "Error: Bind failure\n", EXIT_FAILURE);
    fprintf(stderr, "bound: %d\n", status);
    
    /* Ask the kernel to make it a listening socket with a queue of 10 */
    status = listen(server_socket, 10);
    EXIT_ON_FAIL(status, -1, "Error: Could not listen on socket\n", EXIT_FAILURE);
    fprintf(stderr, "listening: %d\n", status);
    
    /* Keep listening for connections */
    while (1) {
        struct sockaddr_in client_address;
        int address_size;
        
        /* Wait to accept a new connection from a client */
        int client = accept(server_socket, (SA*)&client_address, &address_size);
        if(errno != EINTR) {
            // lock
            if (pthread_mutex_lock(&(header->mutex)) != 0)
                log_to_file("Error: fail to lock mutex\n");
            
            header->total_request++;
            
            // unlock
            if (pthread_mutex_unlock(&(header->mutex)) != 0)
                log_to_file("Error: fail to unlock mutex");
        }
        
        if(client == -1) {
            respond_msg(-1, "Error: Accept failed\n");
        }
        
        // for error check
        fprintf(stderr, "Accepted.  Client No: %d.  File No: %d\n",  client_number, client);
        
        /* Handle the client's request */
        if (errno != EINTR)
            handle_client(client);
        
        /* Close the client an update our client connection number */
        if (errno != EINTR)
            status = close(client);
        if (status == -1) {
            respond_msg(-1, "Error: fail to close client\n");
        }
        if (errno != EINTR)
            client_number++;
        
        /* Wait for the child to die and get its exit status */
        int child_status = 0;
        if (errno != EINTR)
            //            status = wait(&child_status);
            status = waitpid(-1, &child_status, WNOHANG);
        if (status == -1) {
            respond_msg(-1, "Error: fail to get child status\n");
        }
        
        // for error check
        fprintf(stderr, "total: %d\nsuccess: %d\nnot found:%d\nforbid: %d\nothers: %d\n",
                header->total_request, header->successful_request,
                header->not_found_request, header->forbidden_request, header->others);
        
        // deal with signal SIGINT
        if (is_interrupted == 1) {
            is_interrupted = 0;
            
            status = wait(&child_status);
            if (status == -1) {
                respond_msg(-1, "Error: fail to wait child\n");
            }
            
            // close socket
            status = close(server_socket);
            if (status == -1) {
                respond_msg(-1, "Error: flai to close socket\n");
            }
            
            // close log file
            status = fclose(log_file);
            if (status == -1) {
                respond_msg(-1, "Error: fail to close log file\n");
            }
            
            // close program
            exit(EXIT_SUCCESS);
        }
    }
}
