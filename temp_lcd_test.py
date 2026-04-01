import os, importlib, sys
sys.path.insert(0, r'c:/Users/ilike/Documents/GitHub/Raspyjack')
os.environ['RJ_LCD_MODEL']='1in54'
for m in ['LCD_1in44', 'LCD_1in54']:
    sys.modules.pop(m, None)
mod=importlib.import_module('LCD_1in44')
print('WIDTH', mod.LCD_WIDTH, 'HEIGHT', mod.LCD_HEIGHT)
lcd=mod.LCD()
print(lcd.width, lcd.height)
