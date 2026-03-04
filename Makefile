# ============================================================================
# Sentinel - Advanced Port Scanner
# Makefile for production build
# Author: djhelski
# License: MIT
# ============================================================================

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic -Werror
OPTFLAGS = -O3 -flto -march=native -mtune=native
DEBUGFLAGS = -g -O0 -DDEBUG -fsanitize=address -fsanitize=undefined
LDFLAGS = -pthread
STATIC_FLAGS = -static -static-libgcc -static-libstdc++

# Directories
SRCDIR = src
BINDIR = bin
DOCDIR = docs
EXAMPLEDIR = examples

# Files
TARGET = sentinel
SOURCES = $(SRCDIR)/sentinel.cpp
HEADERS = $(SRCDIR)/scanner.h $(SRCDIR)/types.h
OBJECTS = $(BINDIR)/sentinel.o

# Version
VERSION = 2.0.0
BUILD_DATE = $(shell date +'%Y-%m-%d %H:%M:%S')
GIT_HASH = $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[0;33m
BLUE = \033[0;34m
NC = \033[0m # No Color

# ============================================================================
# Targets
# ============================================================================

.PHONY: all
all: banner dirs release info

.PHONY: banner
banner:
	@echo ""
	@echo "$(BLUE)╔════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║              S E N T I N E L                   ║$(NC)"
	@echo "$(BLUE)║        Advanced Port Scanner v$(VERSION)               ║$(NC)"
	@echo "$(BLUE)╚════════════════════════════════════════════════╝$(NC)"
	@echo ""

.PHONY: dirs
dirs:
	@mkdir -p $(BINDIR)
	@mkdir -p $(DOCDIR)
	@mkdir -p $(EXAMPLEDIR)

# ============================================================================
# Build targets
# ============================================================================

.PHONY: release
release: CXXFLAGS += $(OPTFLAGS)
release: $(BINDIR)/$(TARGET)
	@echo "$(GREEN)✅ Release build complete: $(BINDIR)/$(TARGET)$(NC)"
	@$(MAKE) info

.PHONY: debug
debug: CXXFLAGS += $(DEBUGFLAGS)
debug: $(BINDIR)/$(TARGET)-debug
	@echo "$(YELLOW)🔧 Debug build complete: $(BINDIR)/$(TARGET)-debug$(NC)"

.PHONY: static
static: CXXFLAGS += $(OPTFLAGS) $(STATIC_FLAGS)
static: LDFLAGS += $(STATIC_FLAGS)
static: $(BINDIR)/$(TARGET)-static
	@echo "$(GREEN)📦 Static build complete: $(BINDIR)/$(TARGET)-static$(NC)"

.PHONY: profile
profile: CXXFLAGS += $(OPTFLAGS) -pg
profile: $(BINDIR)/$(TARGET)-profile
	@echo "$(YELLOW)📊 Profile build complete: $(BINDIR)/$(TARGET)-profile$(NC)"

.PHONY: sanitize
sanitize: CXXFLAGS += $(DEBUGFLAGS) -fsanitize=thread
sanitize: $(BINDIR)/$(TARGET)-sanitize
	@echo "$(RED)🧪 Sanitizer build complete: $(BINDIR)/$(TARGET)-sanitize$(NC)"

.PHONY: minimal
minimal: CXXFLAGS = -std=c++17 -Os -s
minimal: LDFLAGS = -pthread -s
minimal: $(BINDIR)/$(TARGET)-minimal
	@echo "$(BLUE)⚡ Minimal build complete: $(BINDIR)/$(TARGET)-minimal$(NC)"

# ============================================================================
# Compilation rules
# ============================================================================

$(BINDIR)/$(TARGET): $(SOURCES) $(HEADERS)
	@echo "$(YELLOW)🔨 Building release version...$(NC)"
	$(CXX) $(CXXFLAGS) -o $@ $(SOURCES) $(LDFLAGS)
	@strip $@
	@echo "$(GREEN)✅ Done$(NC)"

$(BINDIR)/$(TARGET)-debug: $(SOURCES) $(HEADERS)
	@echo "$(YELLOW)🔨 Building debug version...$(NC)"
	$(CXX) $(CXXFLAGS) -o $@ $(SOURCES) $(LDFLAGS)
	@echo "$(GREEN)✅ Done$(NC)"

$(BINDIR)/$(TARGET)-static: $(SOURCES) $(HEADERS)
	@echo "$(YELLOW)🔨 Building static version...$(NC)"
	$(CXX) $(CXXFLAGS) -o $@ $(SOURCES) $(LDFLAGS)
	@strip $@
	@echo "$(GREEN)✅ Done$(NC)"

$(BINDIR)/$(TARGET)-profile: $(SOURCES) $(HEADERS)
	@echo "$(YELLOW)🔨 Building profile version...$(NC)"
	$(CXX) $(CXXFLAGS) -o $@ $(SOURCES) $(LDFLAGS)
	@echo "$(GREEN)✅ Done$(NC)"

$(BINDIR)/$(TARGET)-sanitize: $(SOURCES) $(HEADERS)
	@echo "$(YELLOW)🔨 Building sanitizer version...$(NC)"
	$(CXX) $(CXXFLAGS) -o $@ $(SOURCES) $(LDFLAGS)
	@echo "$(GREEN)✅ Done$(NC)"

$(BINDIR)/$(TARGET)-minimal: $(SOURCES) $(HEADERS)
	@echo "$(YELLOW)🔨 Building minimal version...$(NC)"
	$(CXX) $(CXXFLAGS) -o $@ $(SOURCES) $(LDFLAGS)
	@echo "$(GREEN)✅ Done$(NC)"

# ============================================================================
# Helper targets
# ============================================================================

.PHONY: info
info:
	@echo ""
	@echo "$(BLUE)📋 Build Information:$(NC)"
	@echo "  Version:    $(VERSION)"
	@echo "  Git hash:   $(GIT_HASH)"
	@echo "  Build date: $(BUILD_DATE)"
	@echo "  Compiler:   $(CXX) $(shell $(CXX) --version | head -n1)"
	@echo "  Flags:      $(CXXFLAGS)"
	@echo "  Output:     $(BINDIR)/$(TARGET)"
	@echo "  Size:       $$(du -h $(BINDIR)/$(TARGET) | cut -f1)"
	@echo ""

.PHONY: run
run: release
	@echo "$(YELLOW)🚀 Running Sentinel...$(NC)"
	@echo ""
	@$(BINDIR)/$(TARGET) -t 8.8.8.8 -p 53,80,443
	@echo ""

.PHONY: test
test: debug
	@echo "$(YELLOW)🧪 Running tests...$(NC)"
	@echo ""
	@$(BINDIR)/$(TARGET)-debug -t 127.0.0.1 -p 1-100 -v

.PHONY: benchmark
benchmark: release
	@echo "$(YELLOW)⏱️  Running benchmark...$(NC)"
	@echo ""
	@time $(BINDIR)/$(TARGET) -t 8.8.8.8 -p 1-1000 --rate 1000

.PHONY: clean
clean:
	@echo "$(RED)🧹 Cleaning...$(NC)"
	@rm -rf $(BINDIR)
	@rm -f *.log *.prof *.gcda *.gcno
	@echo "$(GREEN)✅ Clean complete$(NC)"

.PHONY: distclean
distclean: clean
	@rm -rf *.tar.gz *.zip
	@find . -name "*~" -delete
	@find . -name "*.bak" -delete

.PHONY: install
install: release
	@echo "$(YELLOW)📦 Installing to /usr/local/bin/...$(NC)"
	@sudo cp $(BINDIR)/$(TARGET) /usr/local/bin/
	@sudo chmod +x /usr/local/bin/$(TARGET)
	@echo "$(GREEN)✅ Installation complete$(NC)"

.PHONY: uninstall
uninstall:
	@echo "$(RED)🗑️  Uninstalling...$(NC)"
	@sudo rm -f /usr/local/bin/$(TARGET)
	@echo "$(GREEN)✅ Uninstall complete$(NC)"

.PHONY: package
package: release
	@echo "$(YELLOW)📦 Creating distribution package...$(NC)"
	@tar -czf sentinel-$(VERSION).tar.gz $(BINDIR)/$(TARGET) LICENSE README.md
	@zip -q sentinel-$(VERSION).zip $(BINDIR)/$(TARGET) LICENSE README.md
	@echo "$(GREEN)✅ Package created: sentinel-$(VERSION).tar.gz$(NC)"

.PHONY: docs
docs:
	@echo "$(YELLOW)📚 Generating documentation...$(NC)"
	@doxygen Doxyfile 2>/dev/null || echo "Doxygen not installed"
	@echo "$(GREEN)✅ Documentation generated$(NC)"

.PHONY: format
format:
	@echo "$(YELLOW)✨ Formatting code...$(NC)"
	@clang-format -i $(SOURCES) $(HEADERS) 2>/dev/null || echo "clang-format not installed"
	@echo "$(GREEN)✅ Formatting complete$(NC)"

.PHONY: lint
lint:
	@echo "$(YELLOW)🔍 Running linter...$(NC)"
	@cppcheck --enable=all --suppress=missingIncludeSystem $(SOURCES) 2>/dev/null || echo "cppcheck not installed"
	@echo "$(GREEN)✅ Lint complete$(NC)"

.PHONY: help
help:
	@echo ""
	@echo "$(BLUE)📖 Sentinel Makefile Help$(NC)"
	@echo ""
	@echo "  $(GREEN)Build targets:$(NC)"
	@echo "    make           - Default build (release)"
	@echo "    make release   - Optimized release build"
	@echo "    make debug     - Debug build with symbols"
	@echo "    make static    - Fully static build"
	@echo "    make profile   - Build with profiling"
	@echo "    make sanitize  - Build with thread sanitizer"
	@echo "    make minimal   - Minimal size build"
	@echo ""
	@echo "  $(GREEN)Utility targets:$(NC)"
	@echo "    make run       - Run a quick test scan"
	@echo "    make test      - Run debug test"
	@echo "    make benchmark - Run performance test"
	@echo "    make clean     - Clean build directory"
	@echo "    make distclean - Clean everything"
	@echo ""
	@echo "  $(GREEN)Installation:$(NC)"
	@echo "    make install   - Install to /usr/local/bin"
	@echo "    make uninstall - Remove from system"
	@echo ""
	@echo "  $(GREEN)Development:$(NC)"
	@echo "    make docs      - Generate documentation"
	@echo "    make format    - Format source code"
	@echo "    make lint      - Run static analysis"
	@echo "    make package   - Create distribution package"
	@echo "    make info      - Show build information"
	@echo ""

# ============================================================================
# Dependencies
# ============================================================================

$(BINDIR)/sentinel.o: $(SRCDIR)/sentinel.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# ============================================================================
# Default target
# ============================================================================

.DEFAULT_GOAL := all

# ============================================================================
# Special targets
# ============================================================================

.SILENT:
.ONESHELL:
.NOTPARALLEL:
