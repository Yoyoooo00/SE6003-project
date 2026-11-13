# Makefile for SE6003 RSA-OAEP Project (Python 3)

.PHONY: all test bench clean

# Default target (does nothing since Python doesn't compile, but satisfies requirements)
all:
	@echo "Python is interpreted. No compilation needed."
	@echo "Run 'make test' to run unit tests."
	@echo "Run 'make bench' to run benchmarks."

# Run unit tests
test:
	python3 -m unittest -v test_rsa_oaep.py

# Run benchmark
bench:
	python3 bench.py

# Clean up Python cache files
clean:
	rm -rf __pycache__/
	rm -rf *.pyc
