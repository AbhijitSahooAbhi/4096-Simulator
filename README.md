
# **4096-Processor Simulator**  

## **Overview**  
The **4096-Processor Simulator** is a Python-based simulation tool designed to emulate the behavior of a large-scale, multi-processor architecture. It provides an interactive environment for executing **assembly-like instructions**, debugging code, and visualizing processor operations.  

This simulator is ideal for students, researchers, and developers looking to understand **parallel computing**, **memory management**, and **assembly instruction execution** in a multi-processor system.  

## **Key Features**  

### **1. Register Display**  
- Displays key registers like **Accumulator, Program Counter, Flags**, and others.  

### **2. Memory Addressing**  
- Shows **memory addresses in hexadecimal** with dynamic updates when storing values.  

### **3. Value Representation**  
- Automatically converts between **Hexadecimal, Decimal, Binary, and Octal**.  

### **4. Assembly Code Execution**  
- Users can input and execute **assembly-like instructions**.  

### **5. Supported Assembly Instructions**  
- Includes a range of **basic and advanced instructions**:  
  - **Data Transfer**: `LOAD`, `STORE`  
  - **Arithmetic Operations**: `ADD`, `SUB`, `MUL`, `DIV`  
  - **Logical Operations**: `AND`, `OR`, `XOR`, `NOT`  
  - **Branching**: `JZ` (Jump if Zero), `JNZ` (Jump if Not Zero), `JMP` (Unconditional Jump)  

### **6. Debugging Mode**  
- Provides **step-by-step execution**, breakpoints, and instruction history for debugging.  

### **7. Visualization Tools**  
- Tracks **data movement** between registers and memory in real-time.  

### **8. Number System Conversion**  
- Converts **Decimal, Hexadecimal, Binary, and Octal** values.  

---

## **Project Structure**  
```
4096-Processor-Simulator/
│── src/  
│   ├── debugger.py                 # Debugging functionalities
│   ├── instruction_processor.py    # Memory management system  
│   ├── memory_manager.py           # Register management module  
│   ├── processor_simulator.py      # Assembly instruction execution   
│   ├── simulator_gui.py            # GUI for visualization (Optional)   
│── README.md  
│── requirements.txt         # Dependencies  
│── LICENSE  
```

---

## **Installation & Setup**  

### **1. Clone the Repository**  
```bash
git clone https://github.com/yourusername/4096-processor-simulator.git
cd 4096-processor-simulator
```

### **2. Install Dependencies**  
Ensure you have **Python 3.8+** installed. Then, install the required dependencies:  
```bash
pip install -r requirements.txt
```

### **3. Run the Simulator**  
```bash
python src/simulator.py
```

---

## **Usage Guide**  

1. **Load an Assembly File**  
   - You can write your own **assembly-like instructions** or use the provided examples.  

2. **Execute Instructions**  
   - Run the program step-by-step or all at once.  

3. **Debug & Analyze**  
   - Use **breakpoints, instruction history, and visualization** tools to analyze execution.  

---

## **Example Assembly Code**  
Below is an example of an assembly-like program to **add two numbers**:  
```
LOAD R1, 10      ; Load value 10 into register R1  
LOAD R2, 5       ; Load value 5 into register R2  
ADD R3, R1, R2   ; Add R1 and R2, store result in R3  
STORE R3, 0x100  ; Store result at memory address 0x100  
```

---

## **Future Enhancements**  
✅ Multi-threaded execution for faster simulation.  
✅ Enhanced **GUI for real-time visualization**.  
✅ **Customizable instruction sets** and new **CPU architectures**.  
✅ Export execution logs for deeper analysis.  

---

## **Contributing**  
Contributions are welcome! To contribute:  
1. **Fork** this repository.  
2. **Create a new branch** (`feature-branch`).  
3. **Commit your changes** and push to your fork.  
4. **Create a Pull Request (PR)** for review.  

---

## **License**  
This project is licensed under the **MIT License**.  

---

## **Contact & Support**  
For questions, feedback, or support, open an **issue** or reach out via email at `abhijit@imit.ac.in`.  

