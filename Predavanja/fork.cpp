#include <iostream>
#include <unistd.h>

int main(int argc, char* argv[])
{
  std::cout << "Orginal prije fork-a: " << getpid() << std::endl;

  int p = fork();

  if (p != 0)
    std::cout << "Ja sam orginal sa PID: " << getpid() << std::endl
              << "Imam child sa PID: " << p << std::endl;
  else
    std::cout << "Ja sam klon :( sa PID: " << getpid() << std::endl;

  std::cout << "foo" << std::endl;

  return 0;
}
