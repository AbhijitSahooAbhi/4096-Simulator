"""
Instruction Processor for the 4096 Processor Simulator
Handles assembly instruction parsing and execution.
"""

class InstructionProcessor:
    """Handles assembly instruction parsing and execution."""
    
    def __init__(self, memory_manager):
        """
        Initialize the instruction processor.
        
        Args:
            memory_manager (MemoryManager): Reference to the memory manager.
        """
        self.memory_manager = memory_manager
        self.accumulator = 0  # Accumulator register
        self.program_counter = 0  # Program counter register
        self.flags = {
            'zero': False,      # Zero flag (Z)
            'negative': False,  # Negative flag (N)
            'carry': False      # Carry flag (C)
        }
        self.instruction_history = []  # Store executed instructions
        self.prev_states = []  # For step-back functionality
        self.instructions = []  # Parsed instructions
        self.breakpoints = set()  # Set of line numbers for breakpoints
        
    def save_state(self):
        """Save the current processor state for step-back functionality."""
        state = {
            'accumulator': self.accumulator,
            'program_counter': self.program_counter,
            'flags': self.flags.copy()
        }
        self.prev_states.append(state)
        # Keep only the last 20 states to avoid excessive memory usage
        if len(self.prev_states) > 20:
            self.prev_states.pop(0)
    
    def restore_previous_state(self):
        """Restore the previous processor state."""
        if self.prev_states:
            state = self.prev_states.pop()
            self.accumulator = state['accumulator']
            self.program_counter = state['program_counter']
            self.flags = state['flags']
            # Also pop the last instruction from history
            if self.instruction_history:
                self.instruction_history.pop()
            return True
        return False
    
    def update_flags(self, result):
        """
        Update flags based on the result of an operation.
        
        Args:
            result (int): The result to base flag updates on.
        """
        # Update zero flag
        self.flags['zero'] = (result == 0)
        
        # Update negative flag (for 16-bit values)
        self.flags['negative'] = ((result & 0x8000) != 0)
    
    def parse_instructions(self, assembly_code):
        """
        Parse assembly code into executable instructions.
        
        Args:
            assembly_code (str): The assembly code to parse.
            
        Returns:
            list: A list of parsed instructions.
        """
        self.instructions = []
        
        # Split the code into lines
        lines = assembly_code.strip().split('\n')
        
        # Process each line
        for line_num, line in enumerate(lines):
            # Remove comments and strip whitespace
            comment_pos = line.find(';')
            if comment_pos >= 0:
                line = line[:comment_pos]
            line = line.strip()
            
            # Skip empty lines
            if not line:
                continue
            
            # Parse the instruction
            parts = line.split()
            opcode = parts[0].upper()
            
            instruction = {
                'line_num': line_num,
                'opcode': opcode,
                'operands': parts[1:] if len(parts) > 1 else [],
                'original': line
            }
            
            self.instructions.append(instruction)
        
        return self.instructions
    
    def execute_instructions(self, assembly_code):
        """
        Execute a sequence of assembly instructions.
        
        Args:
            assembly_code (str): The assembly code to execute.
            
        Returns:
            dict: Results of execution including status and any error messages.
        """
        # Parse the instructions
        self.parse_instructions(assembly_code)
        
        # Reset the program counter
        self.program_counter = 0
        
        # Execute all instructions
        while 0 <= self.program_counter < len(self.instructions):
            result = self.execute_next_instruction()
            
            if result['status'] == 'error':
                return result
                
            if self.program_counter in self.breakpoints:
                return {'status': 'breakpoint', 'message': f"Reached breakpoint at line {self.program_counter + 1}"}
        
        return {'status': 'success', 'message': 'Execution completed successfully'}
    
    def execute_next_instruction(self):
        """
        Execute the next instruction.
        
        Returns:
            dict: Result of execution including status and any error messages.
        """
        # Check if program counter is valid
        if self.program_counter < 0 or self.program_counter >= len(self.instructions):
            return {'status': 'error', 'message': 'Program counter out of bounds'}
        
        # Save current state before execution
        self.save_state()
        
        # Get the instruction to execute
        instruction = self.instructions[self.program_counter]
        
        # Add instruction to history
        self.instruction_history.append(instruction['original'])
        
        # Execute the instruction
        result = self._execute_instruction(instruction)
        
        # If there was no error and the instruction didn't change the PC, increment it
        if result['status'] != 'error' and self.program_counter == instruction['line_num']:
            self.program_counter += 1
            
        return result
    
    def _execute_instruction(self, instruction):
        """
        Execute a single instruction.
        
        Args:
            instruction (dict): The instruction to execute.
            
        Returns:
            dict: Result of execution including status and any error messages.
        """
        opcode = instruction['opcode']
        operands = instruction['operands']
        
        try:
            if opcode == 'LOAD':
                if len(operands) != 1:
                    return {'status': 'error', 'message': 'LOAD requires one operand'}
                
                # Check if operand is a memory address (e.g., [100])
                if operands[0].startswith('[') and operands[0].endswith(']'):
                    address = int(operands[0][1:-1], 0)
                    self.accumulator = self.memory_manager.read(address)
                else:
                    # Immediate value
                    self.accumulator = int(operands[0], 0)
                
                self.update_flags(self.accumulator)
                
            elif opcode == 'STORE':
                if len(operands) != 1:
                    return {'status': 'error', 'message': 'STORE requires one operand'}
                
                if operands[0].startswith('[') and operands[0].endswith(']'):
                    address = int(operands[0][1:-1], 0)
                    self.memory_manager.write(address, self.accumulator)
                else:
                    return {'status': 'error', 'message': 'STORE operand must be a memory address [...]'}
                
            elif opcode == 'ADD':
                if len(operands) != 1:
                    return {'status': 'error', 'message': 'ADD requires one operand'}
                
                if operands[0].startswith('[') and operands[0].endswith(']'):
                    address = int(operands[0][1:-1], 0)
                    value = self.memory_manager.read(address)
                else:
                    value = int(operands[0], 0)
                
                # Calculate the result and detect carry
                result = self.accumulator + value
                self.flags['carry'] = (result > 0xFFFF)
                
                # Apply 16-bit mask
                self.accumulator = result & 0xFFFF
                self.update_flags(self.accumulator)
                
            elif opcode == 'SUB':
                if len(operands) != 1:
                    return {'status': 'error', 'message': 'SUB requires one operand'}
                
                if operands[0].startswith('[') and operands[0].endswith(']'):
                    address = int(operands[0][1:-1], 0)
                    value = self.memory_manager.read(address)
                else:
                    value = int(operands[0], 0)
                
                # Calculate the result and detect borrow
                result = self.accumulator - value
                self.flags['carry'] = (result < 0)
                
                # Apply 16-bit mask (wrap around if negative)
                self.accumulator = result & 0xFFFF
                self.update_flags(self.accumulator)
                
            elif opcode == 'MUL':
                if len(operands) != 1:
                    return {'status': 'error', 'message': 'MUL requires one operand'}
                
                if operands[0].startswith('[') and operands[0].endswith(']'):
                    address = int(operands[0][1:-1], 0)
                    value = self.memory_manager.read(address)
                else:
                    value = int(operands[0], 0)
                
                # Calculate the result and detect overflow
                result = self.accumulator * value
                self.flags['carry'] = (result > 0xFFFF)
                
                # Apply 16-bit mask
                self.accumulator = result & 0xFFFF
                self.update_flags(self.accumulator)
                
            elif opcode == 'DIV':
                if len(operands) != 1:
                    return {'status': 'error', 'message': 'DIV requires one operand'}
                
                if operands[0].startswith('[') and operands[0].endswith(']'):
                    address = int(operands[0][1:-1], 0)
                    value = self.memory_manager.read(address)
                else:
                    value = int(operands[0], 0)
                
                if value == 0:
                    return {'status': 'error', 'message': 'Division by zero'}
                
                self.accumulator = (self.accumulator // value) & 0xFFFF
                self.update_flags(self.accumulator)
                
            elif opcode == 'AND':
                if len(operands) != 1:
                    return {'status': 'error', 'message': 'AND requires one operand'}
                
                if operands[0].startswith('[') and operands[0].endswith(']'):
                    address = int(operands[0][1:-1], 0)
                    value = self.memory_manager.read(address)
                else:
                    value = int(operands[0], 0)
                
                self.accumulator = (self.accumulator & value) & 0xFFFF
                self.update_flags(self.accumulator)
                
            elif opcode == 'OR':
                if len(operands) != 1:
                    return {'status': 'error', 'message': 'OR requires one operand'}
                
                if operands[0].startswith('[') and operands[0].endswith(']'):
                    address = int(operands[0][1:-1], 0)
                    value = self.memory_manager.read(address)
                else:
                    value = int(operands[0], 0)
                
                self.accumulator = (self.accumulator | value) & 0xFFFF
                self.update_flags(self.accumulator)
                
            elif opcode == 'XOR':
                if len(operands) != 1:
                    return {'status': 'error', 'message': 'XOR requires one operand'}
                
                if operands[0].startswith('[') and operands[0].endswith(']'):
                    address = int(operands[0][1:-1], 0)
                    value = self.memory_manager.read(address)
                else:
                    value = int(operands[0], 0)
                
                self.accumulator = (self.accumulator ^ value) & 0xFFFF
                self.update_flags(self.accumulator)
                
            elif opcode == 'NOT':
                if len(operands) != 0:
                    return {'status': 'error', 'message': 'NOT does not require operands'}
                
                self.accumulator = (~self.accumulator) & 0xFFFF
                self.update_flags(self.accumulator)
                
            elif opcode == 'JMP':
                if len(operands) != 1:
                    return {'status': 'error', 'message': 'JMP requires one operand'}
                
                line_num = int(operands[0])
                
                if 1 <= line_num <= len(self.instructions):
                    self.program_counter = line_num - 1  # Lines are 1-indexed for the user
                else:
                    return {'status': 'error', 'message': f'Jump target {line_num} out of bounds'}
                
            elif opcode == 'JZ':
                if len(operands) != 1:
                    return {'status': 'error', 'message': 'JZ requires one operand'}
                
                if self.flags['zero']:
                    line_num = int(operands[0])
                    
                    if 1 <= line_num <= len(self.instructions):
                        self.program_counter = line_num - 1  # Lines are 1-indexed for the user
                    else:
                        return {'status': 'error', 'message': f'Jump target {line_num} out of bounds'}
                
            elif opcode == 'JNZ':
                if len(operands) != 1:
                    return {'status': 'error', 'message': 'JNZ requires one operand'}
                
                if not self.flags['zero']:
                    line_num = int(operands[0])
                    
                    if 1 <= line_num <= len(self.instructions):
                        self.program_counter = line_num - 1  # Lines are 1-indexed for the user
                    else:
                        return {'status': 'error', 'message': f'Jump target {line_num} out of bounds'}
                
            else:
                return {'status': 'error', 'message': f'Unknown instruction: {opcode}'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'Error executing {opcode}: {str(e)}'}
        
        return {'status': 'success'}
    
    def get_accumulator(self):
        """Get the current accumulator value."""
        return self.accumulator
    
    def get_program_counter(self):
        """Get the current program counter value."""
        return self.program_counter
    
    def get_flags(self):
        """Get the current flags."""
        return self.flags
    
    def get_instruction_history(self):
        """Get the instruction execution history."""
        return self.instruction_history
    
    def toggle_breakpoint(self, line_num):
        """
        Toggle a breakpoint at the specified line number.
        
        Args:
            line_num (int): The line number (1-indexed) to toggle breakpoint on.
            
        Returns:
            bool: True if breakpoint was added, False if removed.
        """
        if line_num in self.breakpoints:
            self.breakpoints.remove(line_num)
            return False
        else:
            self.breakpoints.add(line_num)
            return True
    
    def get_breakpoints(self):
        """Get the current breakpoints."""
        return self.breakpoints
    
    def reset(self):
        """Reset the processor state."""
        self.accumulator = 0
        self.program_counter = 0
        self.flags = {
            'zero': False,
            'negative': False,
            'carry': False
        }
        self.instruction_history = []
        self.prev_states = []
