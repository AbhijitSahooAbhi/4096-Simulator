"""
Memory Manager for the 4096 Processor Simulator
Handles memory operations, storage, and retrieval.
"""

class MemoryManager:
    """Handles memory operations for the 4096 processor simulator."""
    
    def __init__(self, memory_size=4096):
        """
        Initialize the memory manager.
        
        Args:
            memory_size (int): The size of the memory in bytes. Defaults to 4096.
        """
        self.memory_size = memory_size
        self.memory = [0] * memory_size
        self.memory_history = []  # For step-back functionality
        
    def save_state(self):
        """Save the current memory state for step-back functionality."""
        self.memory_history.append(self.memory.copy())
        # Keep only the last 20 states to avoid excessive memory usage
        if len(self.memory_history) > 20:
            self.memory_history.pop(0)
    
    def restore_previous_state(self):
        """Restore the previous memory state."""
        if self.memory_history:
            self.memory = self.memory_history.pop()
            return True
        return False
    
    def read(self, address):
        """
        Read a value from memory at the specified address.
        
        Args:
            address (int): The memory address to read from.
            
        Returns:
            int: The value at the specified memory address.
            
        Raises:
            IndexError: If the address is out of bounds.
        """
        if 0 <= address < self.memory_size:
            return self.memory[address]
        else:
            raise IndexError(f"Memory address {address} out of bounds (0-{self.memory_size-1})")
    
    def write(self, address, value):
        """
        Write a value to memory at the specified address.
        
        Args:
            address (int): The memory address to write to.
            value (int): The value to write.
            
        Raises:
            IndexError: If the address is out of bounds.
        """
        # Save current state before modification
        self.save_state()
        
        if 0 <= address < self.memory_size:
            self.memory[address] = value & 0xFFFF  # Ensure the value fits in 16 bits
        else:
            raise IndexError(f"Memory address {address} out of bounds (0-{self.memory_size-1})")
    
    def get_memory_dump(self, start=0, count=100):
        """
        Get a formatted dump of memory contents.
        
        Args:
            start (int): Starting address for the dump. Defaults to 0.
            count (int): Number of memory locations to include. Defaults to 100.
            
        Returns:
            str: A formatted string representing memory contents.
        """
        end = min(start + count, self.memory_size)
        result = []
        
        for address in range(start, end):
            value = self.memory[address]
            # Format: Address (hex): Value (hex)
            result.append(f"{address:04X}: {value:04X}")
            
        return "\n".join(result)
    
    def reset(self):
        """Reset all memory to zero."""
        self.memory = [0] * self.memory_size
        self.memory_history = []
