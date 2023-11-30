#TODO GhidrOM for string constructor
#@author Tianxiu Zhou
#@category Python 3
#@keybinding 
#@menupath 
#@toolbar 

from javax.swing import *
from java.awt import BorderLayout, Toolkit
from ghidra.app.decompiler import DecompInterface, PrettyPrinter, ClangTokenGroup
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet


print("Welcome to GhidrOM string constructor")

decompiler = DecompInterface()
decompiler.openProgram(currentProgram())
currFn = getFunctionContaining(currentAddress())
decomp_rs = decompiler.decompileFunction(currFn, 0, ConsoleTaskMonitor()) # DecompiledResults

tokgroups = decomp_rs.getCCodeMarkup()
target = "std::__cxx11::basic_string"
code = ""
# code = PrettyPrinter(currFn, decomp_rs.getCCodeMarkup(), None).print().getC()
instructions = ""
"""
The PrettyPrinter javadoc is outdated. Looked up the src to find the required third param
PrettyPrinter(fn: Function, tokgroup: ClangTokenGroup, transformer: NameTransformer)
"""

for i in tokgroups.numChildren():
	x = tokgroups.Child(i)
	for j in x.numChildren():
		y = x.Child(j)
		for k in y.numChildren():
			statement_node = y.Child(k)
			statement = str(statement_node)
			code += statement + "\n"
			if not target in str(statement):
				continue

			instructions += "Got instructions for target" + "\n"
			addr = y.getMinAddress()
			while addr <= y.getMaxAddress():
				instr = getInstructionAt(addr)
				instructions += str(instr) + "\n"
				instr = instr.next()

"""
Swing logic to make the window
"""
frame = JFrame("GhidrOM For String Constructor")
text_area = JTextArea("")
text_area.setLineWrap(True)
text_area.setEditable(False)

text = f"""
{code}

//------------------------------------------
Instructions for code units containing target
//------------------------------------------

{instructions}
"""
text_area.setText(text)

main_panel = JPanel()
main_panel.setLayout(BorderLayout())

# button_box = Box.createHorizontalBox()
# exit_btn = JButton("Exit")
# def handle_exit():
# 	frame.dispose()
# exit_btn.addActionListener(handle_exit)
# button_box.add(exit_btn)
# main_panel.add(button_box, BorderLayout.SOUTH)

main_panel.add(JScrollPane(text_area))
frame.getContentPane().add(main_panel)

screen_size = Toolkit.getDefaultToolkit().getScreenSize()
width = int(screen_size.getWidth() * .5)
height = int(screen_size.getHeight() * .75)

x = int((screen_size.getWidth() - width) / 2)
y = int((screen_size.getHeight() - height) / 2)
frame.setLocation(x, y)

frame.setSize(width, height)
frame.setVisible(True)

print("Done!")
