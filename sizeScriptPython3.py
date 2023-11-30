#TODO write a description for this script
#@author Team 7
#@category Python 3
#@keybinding 
#@menupath 
#@toolbar 

from javax.swing import *
from java.awt import BorderLayout, Toolkit
from ghidra.app.decompiler import DecompInterface, PrettyPrinter, ClangTokenGroup
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet

decompiler = DecompInterface()
decompiler.openProgram(currentProgram())
currFn = getFunctionContaining(currentAddress())
decomp_rs = decompiler.decompileFunction(currFn, 0, ConsoleTaskMonitor())

target = "std::__cxx11::basic_string"
code = PrettyPrinter(currFn, decomp_rs.getCCodeMarkup(), None).print().getC()

prevInstructs = []
instructCount = 0
sizeVariables = []

instructions = ""
"""
The PrettyPrinter javadoc is outdated. Looked up the src to find the required third param
PrettyPrinter(fn: Function, tokgroup: ClangTokenGroup, transformer: NameTransformer)
"""
for idx, x in enumerate(decomp_rs.getCCodeMarkup()):
	"""
	TODO: understand the structure of decomp_rs.getCCodeMarkup()
	"""
	# code += PrettyPrinter(currFn, ClangTokenGroup(x), None).print().getC()
	itr =  AddressSet(x.getMinAddress(), x.getMaxAddress()).iterator()
	instructions += f"Token Group {idx}:\n"
	while itr.hasNext(): # loop through address ranges
		itr1 = itr.next().iterator() # loop through addresses
		while itr1.hasNext():
			itr1Obj = itr1.next()

			instr = currentProgram().getListing().getInstructionAt(itr1Obj)
			if instr:
				prevInstructs.append(itr1Obj)
				instructCount += 1
			words = str(instr).split(' ')

			if(words[0] == "CALL"):
				secondWord = words[1]
				secondAddr = currentProgram().getAddressFactory().getAddress(secondWord)
				calledInstr = currentProgram().getListing().getFunctionAt(secondAddr)
				if("size" in str(calledInstr)):
					print(prevInstructs)
					
					secondLastInstruct = prevInstructs[instructCount - 3]
					
					secondLastInstruct = currentProgram().getListing().getInstructionAt(secondLastInstruct)
					print(secondLastInstruct)
					secondLastWords = str(secondLastInstruct).split(',')
					print(secondLastWords)
					sizeVariables.append(secondLastWords[1])

			if instr:
				instructions += str(instr)
				instructions += "\n"
	instructions += "\n"

index = 0
for i in range(len(sizeVariables)):
	newCode = sizeVariables[i] + ".size()"
	code = code.replace("std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size()", newCode, 1)
"""
Swing logic to make the window
"""
frame = JFrame("GhidrOM String Size")
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


