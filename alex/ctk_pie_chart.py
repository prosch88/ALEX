# SPDX-License-Identifier: MIT
#
# Copyright (c) 2024 Akash Bora (Akascape)
#
# Modified by Christian Peter, 2026.

from PIL import Image, ImageDraw, ImageFont
import customtkinter as ctk
import random
import math

class CTkPieChart(ctk.CTkLabel):
    """
    A customtkinter widget for pie chart display.
    Author: Akascape
    Version: 0.1
    """
    
    def __init__(self,
                 master,
                 command=None,
                 values={},
                 **kwargs):

        self.show_percentages = kwargs.pop("show_percentages", True)
        self.arc = None
        self.im = Image.new('RGBA', (1000, 1000))
        
        self.size = kwargs.get('radius') or 200
        
        self.background = kwargs.get('bg_color') or master.cget("fg_color")
        self.border_width = kwargs.get('border_width') or 0
        self.border_color = kwargs.get('border_color') or ctk.ThemeManager.theme["CTkButton"]["border_color"]
        self.width = kwargs.get('line_width') or 20
        self.text_color = kwargs.get('text_color') or None
        self.widget = master
        self.values = {}
                
        self.command = command
        self.bg = master.cget("fg_color")
        
        for i in values:
            self.add(tag=i, draw=False, **values[i])
            
        super().__init__(master, image=self.arc, fg_color=self.background, compound='center', text="")
        self.draw_pie_chart()
        
    def _set_scaling(self, *args, **kwargs):
        super()._set_scaling(*args, **kwargs)

        self.size = int(self._apply_widget_scaling(self.size))
        self.width = int(self._apply_widget_scaling(self.width))
        self.border_width = int(self._apply_widget_scaling(self.border_width))
        
    def _set_appearance_mode(self, mode_string):
        super()._set_appearance_mode(mode_string)
        
    def draw_pie_chart(self, *args):
        
        width = self.width *10
        del self.im
        self.im = Image.new('RGBA', (1000, 1000))
        draw = ImageDraw.Draw(self.im)
        draw.arc((0,0, 990, 990), 0, 360, self.widget._apply_appearance_mode(self.border_color), self.border_width)
        new_angle = -90
        sum_ = 0
        
        for i in self.values.values():
            sum_ += i["value"]
            
        for value in self.values.values():
            old_angle = new_angle
            new_angle = old_angle + (value['value']/sum_) * 360
                
            draw.arc((self.border_width, self.border_width, 990-self.border_width, 990-self.border_width), old_angle, new_angle, value['color'], width)
            
            midpoint_angle = (old_angle + new_angle)/2
            
            xn = yn = (900 - self.border_width)/2
            radians = (990 - self.border_width)/2
            arc_pos = radians / 3
            textpos = arc_pos/1.5
            perc = int(round(value['value']/sum_ * 100))
            
            midpoint1_x = xn + (radians - textpos) * math.cos(math.radians(midpoint_angle))
            midpoint1_y = yn + (radians - textpos) * math.sin(math.radians(midpoint_angle))
            
            if self.show_percentages:
                draw.text((midpoint1_x, midpoint1_y), text=str(perc)+"%", fill=value['text_color'],
                          font=ImageFont.load_default(size=70))
            
        x0 = width+self.border_width
        x1 = 990-width-self.border_width
        
        if x0>x1:
            x1=x0

        draw.arc((x0,x0,x1,x1), 0, 360,
                 self.widget._apply_appearance_mode(self.border_color), self.border_width)
        self.arc = ctk.CTkImage(self.im.resize((self.size, self.size), Image.LANCZOS), size=(self.size, self.size))

        super().configure(image=self.arc)

        
    def add(self, tag, value, color=None, text_color=None, draw=True):
        
        if tag in self.values:
            self.update(tag, value, color, text_color)
            return
        
        if color is None:
            color = "#"+''.join([random.choice('ABCDEF0123456789') for i in range(6)])
            
        if text_color is None:
            if self.is_color_too_bright(color):
                text_color = "black"
            else:
                text_color = "white"
            if self.text_color:
                text_color = self.text_color
                
        self.values.update({tag:{'color': color, 'value': value, 'text_color': text_color}})
        
        if draw:
            self.draw_pie_chart()

    def delete(self, tag):
        if tag in self.values:
            del self.values[tag]
        self.draw_pie_chart()

    def update(self, tag, value=None, color=None, text_color=None):
        if tag in self.values:
            if value:
                self.values[tag]['value'] = value
            if color:
                self.values[tag]['color'] = color
            if text_color:
                self.values[tag]['text_color'] = text_color
            self.draw_pie_chart()       
        super().update()
        
    def cget(self, param):

        if param=="bg_color":
            return self.background
        if param=="border_color":
            return self.border_color
        if param=="border_width":
            return self.border_width
        if param=="line_width":
            return self.width
        if param=="radius":
            return self.size
        if param=="width":
            return super().winfo_width()
        if param=="height":
            return super().winfo_height()
        if param=="values":
            return self.values
        if param=="text":
            raise ValueError(f"No such parameter: {param}")
        if param=="justify":
            raise ValueError(f"No such parameter: {param}")
        if param=="text_color":
            raise ValueError(f"No such parameter: {param}")
        if param=="text_color_disabled":
            raise ValueError(f"No such parameter: {param}")
        if param=="corner_radius":
            raise ValueError(f"No such parameter: {param}")
        if param=="font":
            raise ValueError(f"No such parameter: {param}")
        if param=="image":
            raise ValueError(f"No such parameter: {param}")
        
        return super().cget(param)

    def configure(self, **kwargs):
        
        if "bg_color" in kwargs:
            self.background = kwargs["bg_color"]
            kwargs.update({"fg_color": self.background})
        if "border_color" in kwargs:
            self.border_color = kwargs.pop("border_color")
        if "border_width" in kwargs:
            self.border_width = kwargs.pop("border_width")
        if "radius" in kwargs:
            self.size = kwargs.pop("radius")
        if "values" in kwargs:
            self.values = kwargs.pop("values")
            for i in values:
                self.add(tag=i, draw=False, **values[i])
        if "line_width" in kwargs:
            self.width = kwargs.pop("line_width")
        
        super().configure(**kwargs)
        self.draw_pie_chart()

    def is_color_too_bright(self, hex_color, threshold=100):
        if not hex_color.startswith("#"): return False
        
        hex_color = hex_color.lstrip("#")
        r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        total = (r + g + b) / 3
        
        return True if total > threshold else False

    def get(self, tag=None):
        if tag:
            return self.values[tag]
        return self.values
