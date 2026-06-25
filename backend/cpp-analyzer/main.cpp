#include <chrono>
#include <csignal>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

namespace {
volatile std::sig_atomic_t keep_running = 1;

void handle_signal(int) { keep_running = 0; }
}  // namespace

void logAttack(const std::string& ip) {
    std::ofstream logFile("logs/attacks.log", std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Error opening log file!" << std::endl;
        return;
    }
    logFile << "Suspicious activity detected from: " << ip << std::endl;
}

int main() {
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    std::cout << "C++ analyzer worker started (demo traffic sampling)" << std::endl;

    while (keep_running) {
        logAttack("10.0.0.42");
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }

    std::cout << "C++ analyzer worker stopped" << std::endl;
    return 0;
}
