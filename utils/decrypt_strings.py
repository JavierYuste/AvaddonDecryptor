#Decrypt and annotate strings of Avaddon ransomware (05af0cf40590aef24b28fa04c6b4998b7ab3b7f26e60c507adb84f3d837778f2)
#
# Last tested on Binary Ninja version 2.1.2454-dev

import base64
import string

def decrypt_string(base64_encoded_encrypted_str):
	try:
		base64_decoded_str = base64.b64decode(base64_encoded_encrypted_str)
		decrypted_str = ''

		for byte_tmp in base64_decoded_str:
			decrypted_str += chr((byte_tmp - 0x2) ^ 0x43)

		if decrypted_str.isprintable() and all(c in string.printable for c in decrypted_str):
			return decrypted_str

		return None

	except Exception as e:
		return None

def rename_and_tag_string_constructors(string_var):
	try:
		# Get functions that reference the string
		xref_functions = set(xref.function for xref in current_view.get_code_refs(string_var.start))
		for i, curr_function in enumerate(xref_functions):
			try:
				print(f"Current function: {curr_function}")
				# Check function match
				if len(curr_function.basic_blocks) == 1:
					instr_generator = curr_function.high_level_il.instructions
					instr_list = list(instr_generator)
					if len(instr_list) == 2:
						curr_instr = instr_list[0]
						if (curr_instr.operation == HighLevelILOperation.HLIL_CALL):
							if (len(curr_instr.operands[1]) == 3):
								if (curr_instr.operands[1][1].constant == string_var.start):
									if (all(oper.operation == HighLevelILOperation.HLIL_CONST_PTR for oper in curr_instr.operands[1])):
										if (string_var.length <= curr_instr.operands[1][2].constant):
											curr_instr = instr_list[1]
											if curr_instr.operation == HighLevelILOperation.HLIL_RET and curr_instr.operands[0][0].operation == HighLevelILOperation.HLIL_CALL:
												print(f"Matched function: {curr_function}\n\tCreating tag")
												decrypted_string = decrypt_string(string_var.value)
												print(f"\tDecrypted string: {decrypted_string}")
												# Create tag at function
												tag = current_view.create_tag(current_view.tag_types['Constructor'],
																			  f"Constructor for b64_enc_{decrypted_string}",
																			  True)
												curr_function.add_user_function_tag(tag)
												# Rename function
												new_function_name = f"init_{decrypted_string}_{i}"
												print(f"\tRenaming function to {new_function_name}")
												print(f"\tFunction start: {hex(curr_function.start)}")
												function_symbol = Symbol(SymbolType.FunctionSymbol, curr_function.start, new_function_name)
												print(f"\t{function_symbol}")
												current_view.define_user_symbol(function_symbol)
												# Set comment
												print("\tSetting comment describing function")
												curr_function.set_comment_at(curr_function.start,
																				f"[Script-generated comment] Constructor for a String object that "
																				f"contains a pointer to the string '{string_var.value}'. "
																				f"The object will be located at the address received in the parameter at ecx.")
												# Rename and tag destructor function
												print("\tRenaming and tagging destructor function")
												destr_function = current_view.get_function_at(instr_list[1].operands[0][0].operands[1][2].constant)
												if destr_function is None:
													print("Destructor function has not been recognized, we will create it")
													current_view.add_function(instr_list[1].operands[0][0].operands[1][2].constant)
													current_view.update_analysis_and_wait()
													destr_function = current_view.get_function_at(instr_list[1].operands[0][0].operands[1][2].constant)
													destr_function.set_comment_at(destr_function.start,
																				f"Script-generated function")
												function_symbol = Symbol(SymbolType.FunctionSymbol, destr_function.start, f"destructor_b64_enc_{decrypted_string}_{i}")
												current_view.define_user_symbol(function_symbol)
												tag = current_view.create_tag(current_view.tag_types['Destructor'],
																	f"Destructor for b64_enc_{decrypted_string}", True)
												destr_function.add_user_function_tag(tag)
												# Rename pointer in which the object is located (data_XXX)
												print(f"\tRenaming data symbol at {hex(instr_list[0].operands[1][0].constant)}")
												data_symbol = Symbol(SymbolType.DataSymbol,
																	 instr_list[0].operands[1][0].constant,
																	 f"b64_enc_{decrypted_string}_{i}")
												current_view.define_user_symbol(data_symbol)
			except Exception as e:
				print(e)
				print("Continuing")
				pass
	except Exception as e:
		print(e)

if 'Constructor' not in current_view.tag_types.keys():
	bv.create_tag_type("Constructor", "🔨")
if 'Destructor' not in current_view.tag_types.keys():
	bv.create_tag_type("Destructor", "💣")
for possible_string in current_view.strings:
	# Base64 strings must have a number of characters multiple of 4
	if len(possible_string.value) % 4 == 0:
		try:
			decrypted_string = decrypt_string(possible_string.value)
			if decrypted_string is not None:
				print(f"{possible_string.value} -> {decrypted_string}")
				# Set comment on the string with the decrypted content
				if current_view.get_comment_at(possible_string.start) is None or len(current_view.get_comment_at(possible_string.start)) == 0:
					current_view.set_comment_at(possible_string.start, decrypted_string)
				# Rename symbol
				data_symbol = Symbol(SymbolType.DataSymbol, possible_string.start, f"a{decrypted_string}")
				current_view.define_user_symbol(data_symbol)
				# Rename and tag constructors and destructors
				rename_and_tag_string_constructors(possible_string)

		except Exception as e:
			# Pass if the string cannot be decoded from base64, which means that it is not one of the strings we are looking for
			pass
