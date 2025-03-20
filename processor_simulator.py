#!/usr/bin/env python3
"""
4096 Processor Simulator
Main entry point for the simulator application.
"""
import tkinter as tk
from simulator_gui import SimulatorGUI

def main():
    """Main function to start the processor simulator."""
    root = tk.Tk()
    root.title("4096 Processor Simulator")
    root.geometry("1400x900")  # Increased window size
    root.resizable(True, True)
    
    # Create the simulator GUI
    simulator = SimulatorGUI(root)
    
    # Start the main loop
    root.mainloop()

if __name__ == "__main__":
    main()
