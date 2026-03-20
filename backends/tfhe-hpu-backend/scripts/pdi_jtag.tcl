set TOP_NAME [lindex $::argv 0]
set SERIAL_NUMBER [lindex $::argv 1]

puts "TOP NAME: $TOP_NAME"
puts "SERIAL NUMBER: $SERIAL_NUMBER"

open_hw_manager

connect_hw_server -allow_non_jtag

set found_index -1

set targets [get_hw_targets]
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

    # stage 1 programming
    set_property PROGRAM.FILE $TOP_NAME [get_hw_devices $hw_device]
    program_hw_devices [get_hw_devices $hw_device]
} else {
    puts "Could not find $SERIAL_NUMBER in list of hw targets $targets"
}
