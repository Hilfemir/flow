CC       = gcc
CFLAGS   =
LDFLAGS  = -lpcap
OBJFILES = utilities.o argparse.o flows.o main.o
TARGET   = flow

all : $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)
	
clean:
	rm -f $(OBJFILES) $(TARGET) *~
