set TOP_NAME [lindex $::argv 0]
set SERIAL_NUMBERS [lrange $::argv 1 end]
set BOARD_COUNT [llength $SERIAL_NUMBERS]

puts "INFO: Starting JTAG programming of $BOARD_COUNT board(s)"

open_hw_manager
connect_hw_server -allow_non_jtag

set targets [get_hw_targets]

set board_idx 0
foreach SERIAL_NUMBER $SERIAL_NUMBERS {
    incr board_idx
    puts "INFO: Board $board_idx/$BOARD_COUNT Programming $SERIAL_NUMBER"

    set found_index -1
    for {set i 0} {$i < [llength $targets]} {incr i} {
        set tg [lindex $targets $i]
        if {[string first $SERIAL_NUMBER $tg] != -1} {
            set found_index $i
            break
        }
    }

    if {$found_index != -1} {
        open_hw_target [lindex $targets $found_index]
        set hw_device [lindex [get_hw_devices] 1]
        current_hw_device [get_hw_devices $hw_device]

        set_property PROGRAM.FILE $TOP_NAME [get_hw_devices $hw_device]
        program_hw_devices [get_hw_devices $hw_device]

        close_hw_target
        puts "INFO: Board $board_idx/$BOARD_COUNT Done"
    } else {
        puts "ERROR: Could not find $SERIAL_NUMBER in list of hw targets $targets"
        close_hw_manager
        exit 1
    }
}

close_hw_manager
puts "INFO: All boards programmed successfully"
