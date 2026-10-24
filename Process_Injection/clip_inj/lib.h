void mycopy(char* dst, const char* src, int size) {
	int x;
	for (x = 0; x < size; x++) {
		*dst = *src;
		dst++;
		src++;
	}
}

int mystrlen(char* a){
	int length = 0;
	while(*a != '\x00'){
		a++;
		length++;
	}
	return length;
}