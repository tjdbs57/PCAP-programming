# 파일 이름과 컴파일러 설정
CC = gcc
CFLAGS = -Wall -g
TARGET = pcap_tcp_sniffer
SRC = pcap_tcp_sniffer.c
HEADER = myheader.h

# 기본 빌드 명령어
$(TARGET): $(SRC) $(HEADER)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) -lpcap

# 실행
run: $(TARGET)
	sudo ./$(TARGET)

# 코드 정리
clean:
	rm -f $(TARGET)
