#include <fcntl.h>
#include <unistd.h>

int main() {
  char buffer[32];
  int device_fd = open("/dev/mysu", O_RDONLY);
  read(device_fd, buffer, 32);
  write(1, buffer, 32);
  close(device_fd);
  return 0;
}
