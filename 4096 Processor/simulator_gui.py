"""
Simulator GUI for the 4096 Processor Simulator
Provides the graphical user interface for the simulator.
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from memory_manager import MemoryManager
from instruction_processor import InstructionProcessor
from debugger import Debugger

class SimulatorGUI:
    """Graphical user interface for the 4096 processor simulator."""
    
    def __init__(self, root):
        """
        Initialize the simulator GUI.
        
        Args:
            root (tk.Tk): The root tkinter window.
        """
        self.root = root
        
        # Initialize components
        self.memory_manager = MemoryManager()
        self.instruction_processor = InstructionProcessor(self.memory_manager)
        self.debugger = Debugger(self.instruction_processor, self.memory_manager)
        
        # Create the GUI
        self._create_gui()
    
    def _create_gui(self):
        """Create the GUI components."""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left panel (registers and flags)
        left_panel = ttk.LabelFrame(main_frame, text="Registers and Flags", padding="10")
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=False, padx=(0, 5))
        
        # Register and flag sections
        self._create_register_section(left_panel)
        self._create_flags_section(left_panel)
        self._create_conversion_tool(left_panel)
        
        # Right panel (memory, assembly, debugging)
        right_panel = ttk.Frame(main_frame, padding="0")
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Memory panel
        memory_panel = ttk.LabelFrame(right_panel, text="Memory", padding="10")
        memory_panel.pack(fill=tk.BOTH, expand=False, pady=(0, 5))
        self._create_memory_section(memory_panel)
        
        # Assembly panel
        assembly_panel = ttk.LabelFrame(right_panel, text="Assembly Code", padding="10")
        assembly_panel.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        self._create_assembly_section(assembly_panel)
        
        # Debugging panel
        debug_panel = ttk.LabelFrame(right_panel, text="Debugging", padding="10")
        debug_panel.pack(fill=tk.BOTH, expand=False)
        self._create_debug_section(debug_panel)
        
        # Initialize the UI with default values
        self._update_ui()
    
    def _create_register_section(self, parent):
        """
        Create the register display section.
        
        Args:
            parent (ttk.Frame): The parent frame.
        """
        register_frame = ttk.Frame(parent, padding="5")
        register_frame.pack(fill=tk.X, expand=False, pady=(0, 10))
        
        # Accumulator
        ttk.Label(register_frame, text="Accumulator (ACC):").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.acc_var = tk.StringVar(value="0000")
        acc_entry = ttk.Entry(register_frame, textvariable=self.acc_var, width=10, state="readonly")
        acc_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Hexadecimal representation
        ttk.Label(register_frame, text="Hex:").grid(row=0, column=2, sticky=tk.W, pady=2)
        self.acc_hex_var = tk.StringVar(value="0x0000")
        acc_hex_entry = ttk.Entry(register_frame, textvariable=self.acc_hex_var, width=10, state="readonly")
        acc_hex_entry.grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Program Counter
        ttk.Label(register_frame, text="Program Counter (PC):").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.pc_var = tk.StringVar(value="0")
        pc_entry = ttk.Entry(register_frame, textvariable=self.pc_var, width=10, state="readonly")
        pc_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Program Counter in hex
        ttk.Label(register_frame, text="Hex:").grid(row=1, column=2, sticky=tk.W, pady=2)
        self.pc_hex_var = tk.StringVar(value="0x0000")
        pc_hex_entry = ttk.Entry(register_frame, textvariable=self.pc_hex_var, width=10, state="readonly")
        pc_hex_entry.grid(row=1, column=3, sticky=tk.W, padx=5, pady=2)
    
    def _create_flags_section(self, parent):
        """
        Create the flags display section.
        
        Args:
            parent (ttk.Frame): The parent frame.
        """
        flags_frame = ttk.LabelFrame(parent, text="Flags", padding="5")
        flags_frame.pack(fill=tk.X, expand=False, pady=(0, 10))
        
        # Zero Flag
        self.zero_flag_var = tk.BooleanVar(value=False)
        zero_flag_check = ttk.Checkbutton(flags_frame, text="Zero (Z)", variable=self.zero_flag_var, state="disabled")
        zero_flag_check.grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        
        # Negative Flag
        self.negative_flag_var = tk.BooleanVar(value=False)
        negative_flag_check = ttk.Checkbutton(flags_frame, text="Negative (N)", variable=self.negative_flag_var, state="disabled")
        negative_flag_check.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Carry Flag
        self.carry_flag_var = tk.BooleanVar(value=False)
        carry_flag_check = ttk.Checkbutton(flags_frame, text="Carry (C)", variable=self.carry_flag_var, state="disabled")
        carry_flag_check.grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
    
    def _create_conversion_tool(self, parent):
        """
        Create the number system conversion tool.
        
        Args:
            parent (ttk.Frame): The parent frame.
        """
        conversion_frame = ttk.LabelFrame(parent, text="Number Conversion", padding="5")
        conversion_frame.pack(fill=tk.BOTH, expand=True)
        
        # Input field
        ttk.Label(conversion_frame, text="Enter Value:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.conversion_input_var = tk.StringVar()
        self.conversion_input_var.trace("w", self._update_conversions)
        conversion_input = ttk.Entry(conversion_frame, textvariable=self.conversion_input_var, width=20)
        conversion_input.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Base selection
        ttk.Label(conversion_frame, text="Input Base:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.base_var = tk.StringVar(value="Decimal")
        base_combo = ttk.Combobox(conversion_frame, textvariable=self.base_var, width=10, 
                                 values=["Decimal", "Hexadecimal", "Binary", "Octal"])
        base_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        base_combo.bind("<<ComboboxSelected>>", lambda e: self._update_conversions())
        
        # Results
        result_frame = ttk.Frame(conversion_frame)
        result_frame.grid(row=2, column=0, columnspan=2, sticky=tk.EW, pady=5)
        
        # Decimal result
        ttk.Label(result_frame, text="Decimal:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.decimal_var = tk.StringVar()
        decimal_entry = ttk.Entry(result_frame, textvariable=self.decimal_var, width=20, state="readonly")
        decimal_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Hexadecimal result
        ttk.Label(result_frame, text="Hexadecimal:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.hex_var = tk.StringVar()
        hex_entry = ttk.Entry(result_frame, textvariable=self.hex_var, width=20, state="readonly")
        hex_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Binary result
        ttk.Label(result_frame, text="Binary:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.binary_var = tk.StringVar()
        binary_entry = ttk.Entry(result_frame, textvariable=self.binary_var, width=20, state="readonly")
        binary_entry.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Octal result
        ttk.Label(result_frame, text="Octal:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.octal_var = tk.StringVar()
        octal_entry = ttk.Entry(result_frame, textvariable=self.octal_var, width=20, state="readonly")
        octal_entry.grid(row=3, column=1, sticky=tk.W, padx=5, pady=2)
    
    def _create_memory_section(self, parent):
        """
        Create the memory display section.
        
        Args:
            parent (ttk.Frame): The parent frame.
        """
        # Memory contents
        memory_frame = ttk.Frame(parent)
        memory_frame.pack(fill=tk.BOTH, expand=True)
        
        # Memory display
        self.memory_text = scrolledtext.ScrolledText(memory_frame, width=40, height=10, wrap=tk.WORD, 
                                                  font=("Courier", 10))
        self.memory_text.pack(fill=tk.BOTH, expand=True)
        self.memory_text.config(state=tk.DISABLED)
        
        # Memory address controls
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, expand=False, pady=(5, 0))
        
        ttk.Label(control_frame, text="Address:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.address_var = tk.StringVar(value="0")
        address_entry = ttk.Entry(control_frame, textvariable=self.address_var, width=8)
        address_entry.pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Label(control_frame, text="Value:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.value_var = tk.StringVar(value="0")
        value_entry = ttk.Entry(control_frame, textvariable=self.value_var, width=8)
        value_entry.pack(side=tk.LEFT, padx=(0, 5))
        
        set_button = ttk.Button(control_frame, text="Set Value", command=self._set_memory_value)
        set_button.pack(side=tk.LEFT, padx=(0, 5))
        
        refresh_button = ttk.Button(control_frame, text="Refresh", command=self._update_memory_display)
        refresh_button.pack(side=tk.LEFT)
    
    def _create_assembly_section(self, parent):
        """
        Create the assembly code section.
        
        Args:
            parent (ttk.Frame): The parent frame.
        """
        # Create a top frame for code editor and immediate execution
        top_frame = ttk.Frame(parent)
        top_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        # Assembly code input - on the left
        code_frame = ttk.LabelFrame(top_frame, text="Assembly Code Editor")
        code_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.assembly_text = scrolledtext.ScrolledText(code_frame, width=50, height=15, wrap=tk.WORD, 
                                                    font=("Courier", 10))
        self.assembly_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Example placeholder text
        example_code = "; Example assembly code\n"
        example_code += "LOAD 42      ; Load 42 into accumulator\n"
        example_code += "STORE [100]  ; Store accumulator value at address 100\n"
        example_code += "LOAD [100]   ; Load value from address 100\n"
        example_code += "ADD 10       ; Add 10 to accumulator\n"
        example_code += "STORE [101]  ; Store result at address 101\n"
        self.assembly_text.insert(tk.END, example_code)
        
        # Execution controls - on the right
        control_frame = ttk.LabelFrame(top_frame, text="Execution Controls")
        control_frame.pack(side=tk.RIGHT, fill=tk.Y, expand=False, padx=(5, 0))
        
        # Make buttons larger and more prominent
        style = ttk.Style()
        style.configure("Execute.TButton", font=("Arial", 11, "bold"))
        
        # Vertical arrangement of buttons in the right panel
        execute_button = ttk.Button(control_frame, text="Execute All Code", 
                                 command=self._execute_all, style="Execute.TButton", width=20)
        execute_button.pack(fill=tk.X, pady=5, padx=10)
        
        execute_selected_button = ttk.Button(control_frame, text="Execute Selected", 
                                         command=self._execute_selected, style="Execute.TButton", width=20)
        execute_selected_button.pack(fill=tk.X, pady=5, padx=10)
        
        step_button = ttk.Button(control_frame, text="Step", command=self._execute_step, width=20)
        step_button.pack(fill=tk.X, pady=5, padx=10)
        
        set_breakpoint_button = ttk.Button(control_frame, text="Toggle Breakpoint", 
                                       command=self._toggle_breakpoint, width=20)
        set_breakpoint_button.pack(fill=tk.X, pady=5, padx=10)
        
        step_back_button = ttk.Button(control_frame, text="Step Back", 
                                   command=self._step_back, width=20)
        step_back_button.pack(fill=tk.X, pady=5, padx=10)
        
        reset_button = ttk.Button(control_frame, text="Reset Simulator", 
                               command=self._reset_simulator, width=20)
        reset_button.pack(fill=tk.X, pady=5, padx=10)
        
        # Instructions Frame
        instruction_frame = ttk.Frame(control_frame)
        instruction_frame.pack(fill=tk.X, pady=10, padx=10)
        
        instruction_text = "To execute a single instruction:\n1. Select the line in the editor\n2. Click 'Execute Selected'"
        ttk.Label(instruction_frame, text=instruction_text, justify=tk.LEFT).pack(anchor=tk.W)
        
        # Instruction history
        history_frame = ttk.LabelFrame(parent, text="Instruction History")
        history_frame.pack(fill=tk.X, expand=False, pady=(0, 5))
        
        self.history_text = scrolledtext.ScrolledText(history_frame, width=50, height=5, wrap=tk.WORD, 
                                                   font=("Courier", 10))
        self.history_text.pack(fill=tk.BOTH, expand=True)
        self.history_text.config(state=tk.DISABLED)
    
    def _create_debug_section(self, parent):
        """
        Create the debugging section.
        
        Args:
            parent (ttk.Frame): The parent frame.
        """
        # Debug output
        self.debug_text = scrolledtext.ScrolledText(parent, width=50, height=5, wrap=tk.WORD, 
                                                 font=("Courier", 10))
        self.debug_text.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        self.debug_text.config(state=tk.DISABLED)
        
        # Debug controls
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, expand=False)
        
        clear_button = ttk.Button(control_frame, text="Clear Debug Output", command=self._clear_debug_output)
        clear_button.pack(side=tk.LEFT)
    
    def _execute_selected(self):
        """Execute only the selected assembly instruction."""
        try:
            # Get the selected text
            try:
                selected_text = self.assembly_text.get(tk.SEL_FIRST, tk.SEL_LAST)
            except tk.TclError:
                # No selection, show error
                messagebox.showinfo("Selection Error", "Please select an instruction to execute")
                return
                
            # Execute the selected instruction
            if selected_text.strip():
                # Save processor state to allow step back
                self.instruction_processor.save_state()
                self.memory_manager.save_state()
                
                # Execute the selected instruction
                result = self.instruction_processor.execute_instructions(selected_text)
                
                if result['status'] == 'error':
                    messagebox.showerror("Execution Error", result['message'])
                elif result['status'] == 'breakpoint':
                    messagebox.showinfo("Breakpoint", result['message'])
                
                # Add to debug output
                self.debugger.debug_output.append(f"Executed: {selected_text.strip()}")
                
                # Update UI
                self._update_ui()
            else:
                messagebox.showinfo("Selection Error", "Please select a valid instruction")
                
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def _update_conversions(self, *args):
        """Update the number system conversions based on input."""
        try:
            # Get input value and base
            input_text = self.conversion_input_var.get().strip()
            base = self.base_var.get()
            
            if not input_text:
                self.decimal_var.set("")
                self.hex_var.set("")
                self.binary_var.set("")
                self.octal_var.set("")
                return
            
            # Convert based on selected base
            value = 0  # Initialize value to avoid 'possibly unbound' error
            if base == "Decimal":
                value = int(input_text, 10)
            elif base == "Hexadecimal":
                # Handle both with and without 0x prefix
                if input_text.lower().startswith("0x"):
                    value = int(input_text, 16)
                else:
                    value = int(input_text, 16)
            elif base == "Binary":
                # Handle both with and without 0b prefix
                if input_text.lower().startswith("0b"):
                    value = int(input_text, 2)
                else:
                    value = int(input_text, 2)
            elif base == "Octal":
                # Handle both with and without 0o prefix
                if input_text.lower().startswith("0o"):
                    value = int(input_text, 8)
                else:
                    value = int(input_text, 8)
            
            # Update all output fields
            self.decimal_var.set(str(value))
            self.hex_var.set(hex(value))
            self.binary_var.set(bin(value))
            self.octal_var.set(oct(value))
            
        except Exception as e:
            # Clear outputs on error
            self.decimal_var.set("Error")
            self.hex_var.set("Error")
            self.binary_var.set("Error")
            self.octal_var.set("Error")
    
    def _execute_all(self):
        """Execute all assembly instructions."""
        try:
            assembly_code = self.assembly_text.get("1.0", tk.END)
            
            result = self.instruction_processor.execute_instructions(assembly_code)
            
            if result['status'] == 'error':
                messagebox.showerror("Execution Error", result['message'])
            elif result['status'] == 'breakpoint':
                messagebox.showinfo("Breakpoint", result['message'])
            
            self._update_ui()
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def _execute_step(self):
        """Execute a single assembly instruction."""
        try:
            # Check if we need to parse instructions first
            if not self.instruction_processor.instructions:
                assembly_code = self.assembly_text.get("1.0", tk.END)
                self.instruction_processor.parse_instructions(assembly_code)
            
            # Execute next instruction
            result = self.debugger.step_execution()
            
            if result['status'] == 'error':
                messagebox.showerror("Execution Error", result['message'])
            
            self._update_ui()
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def _step_back(self):
        """Undo the last instruction execution."""
        if self.debugger.step_back():
            self._update_ui()
        else:
            messagebox.showinfo("Step Back", "No previous state to restore")
    
    def _toggle_breakpoint(self):
        """Toggle a breakpoint at the current line."""
        try:
            # Get the current line number
            current_line = self.assembly_text.index(tk.INSERT).split('.')[0]
            line_num = int(current_line)
            
            # Toggle the breakpoint
            added = self.debugger.toggle_breakpoint(line_num)
            
            if added:
                messagebox.showinfo("Breakpoint", f"Breakpoint added at line {line_num}")
            else:
                messagebox.showinfo("Breakpoint", f"Breakpoint removed from line {line_num}")
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def _set_memory_value(self):
        """Set a value in memory at the specified address."""
        try:
            address = int(self.address_var.get(), 0)  # Parse as int with auto base detection
            value = int(self.value_var.get(), 0)
            
            self.memory_manager.write(address, value)
            self._update_memory_display()
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def _update_memory_display(self):
        """Update the memory display."""
        self.memory_text.config(state=tk.NORMAL)
        self.memory_text.delete("1.0", tk.END)
        
        # Get memory dump starting from address 0
        memory_dump = self.memory_manager.get_memory_dump(0, 100)
        self.memory_text.insert(tk.END, memory_dump)
        
        self.memory_text.config(state=tk.DISABLED)
    
    def _clear_debug_output(self):
        """Clear the debug output."""
        self.debug_text.config(state=tk.NORMAL)
        self.debug_text.delete("1.0", tk.END)
        self.debug_text.config(state=tk.DISABLED)
    
    def _reset_simulator(self):
        """Reset the simulator state."""
        self.memory_manager.reset()
        self.instruction_processor.reset()
        self.debugger.reset()
        
        # Keep the assembly code but clear history
        self.history_text.config(state=tk.NORMAL)
        self.history_text.delete("1.0", tk.END)
        self.history_text.config(state=tk.DISABLED)
        
        self._clear_debug_output()
        self._update_ui()
        
        messagebox.showinfo("Reset", "Simulator has been reset")
    
    def _update_ui(self):
        """Update all UI components with current state."""
        # Update register displays
        acc = self.instruction_processor.get_accumulator()
        pc = self.instruction_processor.get_program_counter()
        flags = self.instruction_processor.get_flags()
        
        self.acc_var.set(f"{acc:d}")
        self.acc_hex_var.set(f"0x{acc:04X}")
        self.pc_var.set(f"{pc:d}")
        self.pc_hex_var.set(f"0x{pc:04X}")
        
        # Update flags
        self.zero_flag_var.set(flags['zero'])
        self.negative_flag_var.set(flags['negative'])
        self.carry_flag_var.set(flags['carry'])
        
        # Update memory display
        self._update_memory_display()
        
        # Update instruction history
        history = self.instruction_processor.get_instruction_history()
        
        self.history_text.config(state=tk.NORMAL)
        self.history_text.delete("1.0", tk.END)
        for i, instr in enumerate(history):
            self.history_text.insert(tk.END, f"{i+1}: {instr}\n")
        self.history_text.config(state=tk.DISABLED)
        
        # Update debug output
        debug_output = self.debugger.get_debug_output()
        
        self.debug_text.config(state=tk.NORMAL)
        self.debug_text.delete("1.0", tk.END)
        for msg in debug_output:
            self.debug_text.insert(tk.END, f"{msg}\n")
        self.debug_text.config(state=tk.DISABLED)
        
        # Auto-scroll debug output to the end
        self.debug_text.see(tk.END)
