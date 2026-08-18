#!/bin/bash
set -e

echo "=== 1. Downloading and installing LunarG Vulkan SDK (No apt required) ==="
cd ~
if [ ! -f "vulkan_sdk.tar.gz" ]; then
    wget https://sdk.lunarg.com/sdk/download/latest/linux/vulkan_sdk.tar.gz -O vulkan_sdk.tar.gz
fi
tar -xf vulkan_sdk.tar.gz

# Automatically locate the extracted SDK directory
VULKAN_SDK_DIR="$HOME/$(ls -d 1.3.*/ | head -n 1)x86_64"
echo "Vulkan SDK installed at: $VULKAN_SDK_DIR"

# Persist environment variables in ~/.bashrc if not already present
if ! grep -q "VULKAN_SDK=" ~/.bashrc; then
    echo "export VULKAN_SDK=\"$VULKAN_SDK_DIR\"" >> ~/.bashrc
    echo 'export PATH="$VULKAN_SDK/bin:$PATH"' >> ~/.bashrc
    echo 'export LD_LIBRARY_PATH="$VULKAN_SDK/lib:$LD_LIBRARY_PATH"' >> ~/.bashrc
    echo 'export PKG_CONFIG_PATH="$VULKAN_SDK/lib/pkgconfig:$PKG_CONFIG_PATH"' >> ~/.bashrc
fi

# Export for current session
export VULKAN_SDK="$VULKAN_SDK_DIR"
export PATH="$VULKAN_SDK/bin:$PATH"
export LD_LIBRARY_PATH="$VULKAN_SDK/lib:$LD_LIBRARY_PATH"
export PKG_CONFIG_PATH="$VULKAN_SDK/lib/pkgconfig:$PKG_CONFIG_PATH"

echo "=== 2. Downloading and extracting llama.cpp source ==="
cd ~
if [ -d "llama.cpp" ]; then
    echo "llama.cpp directory already exists. Skipping download."
    cd llama.cpp
else
    wget https://github.com/ggml-org/llama.cpp/archive/refs/heads/master.tar.gz -O llama.cpp.tar.gz
    tar -xzf llama.cpp.tar.gz
    mv llama.cpp-master llama.cpp
    cd llama.cpp
fi

echo "=== 3. Building llama.cpp with Vulkan and AVX support (Xeon E5-2660 v2) ==="
cmake -S . -B build \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DGGML_VULKAN=ON \
    -DGGML_AVX=ON \
    -DGGML_FMA=ON \
    -DGGML_F16C=ON \
    -DLLAMA_BUILD_TESTS=OFF

cmake --build build -j"$(nproc)"

echo "=== 4. Setting up model directory ==="
mkdir -p ~/models

echo "=========================================="
echo "Select which 8B Q4_K_M model you want to download:"
echo "1) Llama 3.2 8B Instruct (General productivity & automation)"
echo "2) LFM 2.5 8B A1B (Liquid AI Hybrid model, massive context & tools)"
echo "3) Granite 4.1 8B (IBM long-context, code & RAG specialist)"
echo "4) Skip model download for now"
echo "=========================================="
read -p "Enter your choice [1-4]: " model_choice

case $model_choice in
    1)
        echo "Downloading Llama 3.2 8B Instruct (Q4_K_M)..."
        wget -O ~/models/model.gguf "https://huggingface.co/mradermacher/Llama-3.2-8B-Instruct-GGUF/resolve/main/Llama-3.2-8B-Instruct.Q4_K_M.gguf"
        ;;
    2)
        echo "Downloading LFM 2.5 8B A1B (Q4_K_M)..."
        wget -O ~/models/model.gguf "https://huggingface.co/LiquidAI/LFM2.5-8B-A1B-GGUF/resolve/main/LFM2.5-8B-A1B-Q4_K_M.gguf"
        ;;
    3)
        echo "Downloading Granite 4.1 8B (Q4_K_M)..."
        wget -O ~/models/model.gguf "https://huggingface.co/unsloth/granite-4.1-8b-GGUF/resolve/main/granite-4.1-8b-Q4_K_M.gguf"
        ;;
    *)
        echo "Skipping model download. Make sure to place your custom GGUF at ~/models/model.gguf later."
        ;;
esac

echo "=== 5. Creating run-server script for your agent ==="
cat << 'EOF' > ~/llama.cpp/run_agent_server.sh
#!/bin/bash
MODEL_PATH="$HOME/models/model.gguf"

if [ ! -f "$MODEL_PATH" ]; then
    echo "Error: Model file not found at $MODEL_PATH"
    echo "Please place your 8B GGUF model there before running."
    exit 1
fi

# Load Vulkan SDK runtime paths
VULKAN_SDK_DIR="$HOME/$(ls -d 1.3.*/ | head -n 1)x86_64"
export VULKAN_SDK="$VULKAN_SDK_DIR"
export LD_LIBRARY_PATH="$VULKAN_SDK/lib:$LD_LIBRARY_PATH"

# Run server with RX 580 offload (-ngl 99), 4096 context, and 10 physical cores (-t 10)
./build/bin/llama-server \
    -m "$MODEL_PATH" \
    -ngl 99 \
    -c 4096 \
    -t 10 \
    --host 127.0.0.1 \
    --port 8080
EOF

chmod +x ~/llama.cpp/run_agent_server.sh

echo "=========================================="
echo "Setup successfully completed!"
echo "1. Verify your Video: ~/llama.cpp/build/bin/llama-cli --list-devices"
echo "2. Run your agent server using: ~/llama.cpp/run_agent_server.sh"
echo "=========================================="
