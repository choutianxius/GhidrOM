#TODO GhidrOM for string constructor
#@author Vyom Gupta
#@category Python 3
#@keybinding 
#@menupath 
#@toolbar 

from javax.swing import *
from java.awt import BorderLayout, Toolkit
from ghidra.app.decompiler import DecompInterface, PrettyPrinter, ClangTokenGroup
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet

import os
print(os.getcwd())

print("Welcome to GhidrOM string String Accessor Mapper")

decompiler = DecompInterface()
decompiler.openProgram(currentProgram())
currFn = getFunctionContaining(currentAddress())
decomp_rs = decompiler.decompileFunction(currFn, 0, ConsoleTaskMonitor())

target = "std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[]"
code = PrettyPrinter(currFn, decomp_rs.getCCodeMarkup(), None).print().getC()
# print(code)
instructions = ""
"""
The PrettyPrinter javadoc is outdated. Looked up the src to find the required third param
PrettyPrinter(fn: Function, tokgroup: ClangTokenGroup, transformer: NameTransformer)
"""

prevInstructions = list()
instrCount = 0
indexes = list()
arrayVariables = list()

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
			instr = currentProgram().getListing().getInstructionAt(itr1.next())

			if instr:
				prevInstructions.append(instr)
				instrCount += 1

			# print(instr)
			words = str(instr).split(' ')
			# print(words)

			if words[0] == "CALL":
				
				secondWord = words[1]
				secondAddr = currentProgram().getAddressFactory().getAddress(secondWord)
				calledInstr = currentProgram().getListing().getFunctionAt(secondAddr)
				# print("Found call:", calledInstr)
				if "[]" in str(calledInstr):
					print("Found target")
					# print(prevInstructions)
					
					secondLastInstr = prevInstructions[instrCount - 3]
					thirdLastInstr = prevInstructions[instrCount - 4]

					# secondLastInstr = currentProgram().getListing().getInstructionAt(secondLastInstr)
					# print()
					# print()
					# # print("secondLastInstr")
					# print(secondLastInstr)
					# print()
					# print()

					secondLastWords = str(secondLastInstr).split(',')
					thirdLastInstrWords = str(thirdLastInstr).split(',')
					# print(secondLastWords)
					# print(thirdLastInstrWords)
					arrayVariables.append(thirdLastInstrWords[1])


					if secondLastWords[1].startswith('0x'):
						# print("Valid index")
						indexVal = int(secondLastWords[1], 0)
						indexes.append(indexVal)
						print(indexVal)
					else:
						print(secondLastWords[1])
						indexes.append('?')

					

			if instr:
				instructions += str(instr)
				instructions += "\n"
	instructions += "\n"

# print("indexes:", indexes)
# print("arrayVariables:", arrayVariables)

# with open("cleanCode.txt", 'w') as f:
# 	f.write(code)


with open("cleanCode.txt", 'r') as f:
	code1 = f.read()


for i in range(len(indexes)):
	newCode = str(arrayVariables[i]) + "[" + str(indexes[i]) + "]"

	code1 = code1.replace("(char *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::", newCode, 1)
	code1 = code1.replace("operator[]((ulong)", "", 1)

code = code1

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
