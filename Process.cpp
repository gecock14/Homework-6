#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include "Process.hpp"

Process::Process(const std::vector<char*>& args, bool verbose) :
    verbose(verbose),
    m_name(args[0]),
    m_pid((pid_t)NULL),
    m_writepipe {-1,-1},
    m_readpipe {-1,-1},
    m_pwrite((FILE*)NULL),
    m_pread((FILE*)NULL)
{
    if(args[0] == NULL){
	perror("No input");
	throw std::string("No input");
    } else{
	m_name = args[0];
    }

    if(pipe(m_writepipe) < 0 || pipe(m_readpipe) < 0){
	perror("pipe");
	throw std::string("Pipe");
    }

    if ((m_pid = fork()) < 0)
    {
	perror("Process fork");
	throw std::string("Process fork");
    } else if ( m_pid == 0 ) {
	/* child process */
	
	if (close( PARENT_WRITE ) == -1 || close( PARENT_READ ) == -1){
	    	perror("Parent File Desciptors Faled to Close");
	    	throw std::string("Parent File Desciptors Faled to Close);
	}
	if(dup2( CHILD_WRITE, 1) == -1){
		perror("Duplicating CHILD_WRITE Failed");
		throw std::string("Duplicating CHILD_WRITE Failed");		
	}
	if(close( CHILD_WRITE ) == -1){
	    	perror("Child File Desciptors Faled to Close");
	    	throw std::string("Child File Desciptors Faled to Close");		
	}
	if(dup2( CHILD_READ, 0) == -1){
		perror("Duplicating CHILD_READ Failed");
		throw std::string("Duplicating CHILD_READ Failed")
	}
	if(close(CHILD_READ) == -1){
	    	perror("Child File Desciptors Faled to Close");
	    	throw std::string("Child File Desciptors Faled to Close");
	}
	execvp(args[0], const_cast<char**>(&args[0]));
	perror("Process execvp");
	throw std::string("Process execvp");
    } else {
	/* parent process */
	if (verbose)
        std::cerr << "Process " << m_name << ": forked PID " << m_pid << std::endl;
	if(close(CHILD_READ) == -1 || close(CHILD_WRITE) == -1){
	    	perror("Child File Desciptors Faled to Close");
	    	throw std::string("Child File Desciptors Faled to Close");		
	}
	m_pread = fdopen(PARENT_READ, "r");
	if(m_pread == NULL){
	    	perror("Open PARENT_READ Failed");
	    	throw std::string("Open PARENT_READ Failed");
	}
	m_pwrite = fdopen( PARENT_WRITE, "w");
	if(m_pwrite == NULL){
	    	perror("Open PARENT_WRITE Failed");
	    	throw std::string("Open PARENT_WRITE Failed");
	}
    }
};

Process::~Process()
{
    if (verbose)
	std::cerr << "Process " << m_name << ": Entering ~Process()" << std::endl;

    if(fclose(m_pwrite) == EOF){
    	  perror("Closing Read Descriptor Failed");
	  throw std::string("Closing Read Descriptor Failed");
	}
    kill(m_pid, SIGTERM);
    int status;
    pid_t pid = waitpid(m_pid, &status, 0);
    
    
    if (pid < 0)
	perror("~Process waitpid");
	
    if(fclose(m_pread) == EOF){
    	  perror("Open PARENT_READ Failed");
	  throw std::string("Open PARENT_READ Failed");
	}

    if (verbose)
	std::cerr << "Process " << m_name << ": Leaving ~Process()" << std::endl;
};

void Process::write(const std::string& line)
{
    if(fputs(line.c_str(), m_pwrite) == EOF){
    	perror("Puts Failed");
    	throw std::string("Puts Failed");
    }
    if(fflush(m_pwrite) == EOF){
    	perror("Flsuh Failed");
    	throw std::string("Flush Failed");    	
    }
}

std::string Process::read()
{
    std::string line;
    char* mystring = NULL;
    size_t num_bytes;

    if(getline(&mystring. &num_bytes, m_pread) == -1){}
    	perror("Read Failed");
    	throw std::string("Read Failed");
    }
    line = mystring;
    return line;
}
