#!/usr/bin/env python
# -*- coding: latin-1 -*-
# Versão 1.0 - Betha
# DaFirefoxMain.py
 
# The MIT License (MIT)
#
# Copyright (c) 2014 - Ricardo Mantovani - Desenvolvimento Aberto
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
 
# importa modulos
import wx
import wx.grid
import sqlite3
import os
import getpass
import datetime
import platform
from ctypes import *
import glob
import re
import base64
import socket
 
# Cria classe generica de uma WX.Grid
# A classe abaixo faz parte da documentação WXPython oficial
# Este trecho de código é util para manipular a grade
 
class GenericTable(wx.grid.PyGridTableBase):
    def __init__(self, data, rowLabels = None, colLabels = None):
        wx.grid.PyGridTableBase.__init__(self)
        self.data = data
        self.rowLabels = rowLabels
        self.colLabels = colLabels
 
    def GetNumberRows(self):
        return len(self.data)
 
    def GetNumberCols(self):
        return len(self.data[0])
 
    def GetColLabelValue(self, col):
        if self.colLabels:
            return self.colLabels[col]
 
    def GetRowLabelValue(self, row):
        if self.rowLabels:
            return self.rowLabels[row]
 
    def IsEmptyCell(self, row, col):
        return False
 
    def GetValue(self, row, col):
        return self.data[row][col]
 
    def SetValue(self, row, col, value):
        pass   
 
 # Classes de estruturas de senha
class SECItem(Structure):
   _fields_ = [('type',c_uint),('data',c_void_p),('len',c_uint)]


class secuPWData(Structure):
   _fields_ = [('source',c_ubyte),('data',c_char_p)]


(SECWouldBlock, SECFailure, SECSuccess) = (-2, -1, 0)
(PW_NONE, PW_FROMFILE, PW_PLAINTEXT, PW_EXTERNAL) = (0, 1 ,2 ,3)

# Inicializa Grade
dados = []
colLabels = ["Site (Action URL)", "Usuario (User)", "Senha (Password)"]
rowLabels = []
for linha in range(1, 150):
    rowLabels.append(str(linha))

# Captura arquivos no contexto do usuario 
def contexto_usuario():
   appdata = os.getenv('HOME')
   usersdir = appdata+os.sep+".mozilla"+os.sep+'firefox'
   userdir = os.listdir(usersdir)
   dirs=[]
   for u in userdir:
      if os.path.isdir(usersdir + os.sep + u):
         dirs.append(usersdir + os.sep + u)
   return dirs 
   
# Captura o banco de dados signons.sqlite requer Firefox 3 ou superior
def lesignonDB(userpath,dbname):
   chave.NSS_Init(userpath)   
   # Recupera dados de login
   conn = sqlite3.connect(userpath+os.sep+dbname)
   c = conn.cursor()
   c.execute("SELECT * FROM moz_logins;")   
   # Descriptografa dados usando PK11SDR_Decrypt
   for row in c:
      # Retorna nome de usuario aplicando base64
      unome.data  = cast(c_char_p(base64.b64decode(row[6])), c_void_p)
      unome.len   = len(base64.b64decode(row[6]))
      # Retorna senha de usuario aplicando base64
      passwd.data = cast(c_char_p(base64.b64decode(row[7])), c_void_p)
      passwd.len  = len(base64.b64decode(row[7]))
      # Descriptografa usuario  aplicando PK11SDR
      chave.PK11SDR_Decrypt(byref(unome), byref(dectexto), byref(passdados))
      usuario =  string_at(dectexto.data,dectexto.len)
      # Descriptografa senha aplicando PK11SDR
      chave.PK11SDR_Decrypt(byref(passwd), byref(dectexto), byref(passdados))
      senha   = string_at(dectexto.data, dectexto.len)
      captura = [row[1], usuario, senha]
      dados.append(captura)  
   # Fecha conexões
   c.close()
   conn.close()
   chave.NSS_Shutdown()

# Repeura logins no contexto do usuario
abrirPass = contexto_usuario()

# Le SO externa
chave = CDLL("libnss3.so")

# Cria instancia da classe
passdados = secuPWData()
passdados.source = PW_NONE
passdados.data=0

# Cria instancia da estrutura de criptografia
unome = SECItem()
passwd = SECItem()
dectexto = SECItem()

# Retorna arquivos para desencriptar dados
for u in abrirPass:
   signonfiles = glob.glob(u + os.sep + "signons*.*")
   for s in signonfiles:
      (filepath,filename) = os.path.split(s)
      filetype = re.findall('\.(.*)',filename)[0]
      if filetype.lower() == "sqlite":
         lesignonDB(filepath, filename)
 
# Cria classe da grid
class SimpleGrid(wx.grid.Grid):
    def __init__(self, parent):
        wx.grid.Grid.__init__(self, parent, -1, pos=(5, 10), size=(850, 240))
        tableBase = GenericTable(dados, rowLabels, colLabels)
        self.SetTable(tableBase)                   
 
# Cria formulario
class Formulario(wx.Frame):
    def __init__(self, parent):
        # Cria Formulario
        wx.Frame.__init__(self, parent, -1, "DA - Firefox Password Recovery - Desenvolvimento Aberto - 2014", size=(860, 350))
        panel = wx.Panel(self, wx.ID_ANY)
        
        # Centraliza tela
        self.Center()

        # Cria Menu 
        menu = wx.Menu()
        menu.Append(5000, "S&alvar", "Exportar para texto")
        menu.Append(5001, "Sai&r", "Fechar o programa")

        menu1 = wx.Menu()
        menu1.Append(6001, "&Sobre", "Sobre este programa")

        # Cria Barra de menus
        menubarra = wx.MenuBar()
        menubarra.Append(menu, "&Arquivo")
        menubarra.Append(menu1, "&Sobre")
        self.SetMenuBar(menubarra)

        # Barra de status
        statusbar = self.CreateStatusBar(5)

        # Retorna data
        dataA = datetime.datetime.today()
        dataA = dataA.strftime('%d-%b-%Y')

        # Preenche barra de status
        self.SetStatusText("", 0)
        self.SetStatusText(socket.gethostname(), 1)
        self.SetStatusText(getpass.getuser(), 2)
        self.SetStatusText(dataA, 3)
        self.SetStatusText(self.plataforma(), 4)

        # Declara Eventos dos menus
        self.Bind(wx.EVT_MENU, self.OnSalvar, id=5000)
        self.Bind(wx.EVT_MENU, self.OnSair, id=5001)
        self.Bind(wx.EVT_MENU, self.OnSobre, id=6001)
        
        # Cria botões 
        botao1 =   wx.Button(panel, label="Exportar TXT (Export)", pos=(580,280))
        botao1.Bind(wx.EVT_BUTTON, self.OnSalvar)
        
        botao2 =   wx.Button(panel, label="Fechar (Close)", pos=(740,280))
        botao2.Bind(wx.EVT_BUTTON, self.OnSair)
        
        botao3 =   wx.Button(panel, label="Sobre (About)", pos=(20,280))
        botao3.Bind(wx.EVT_BUTTON, self.OnSobre)

        # Cria Grid de dados
        grid = SimpleGrid(panel)
        grid.SetColSize(0, 370)
        grid.SetColSize(1, 260)
        grid.SetColSize(2, 138)

    def plataforma(self):
        sistema = "OS: " + platform.system() + \
                  " - " + platform.release() + \
                  " - " + platform.version()
        return sistema

    # Cria evento para Salvar Arquivo.
    def OnSalvar(self, evt):
        saveFileDialog = wx.FileDialog(self, "Salvar Como", "", "",
                                       "Arquivos Texto (*.txt)|*.txt",
                                       wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT)

        if saveFileDialog.ShowModal() == wx.ID_CANCEL: return

        # Cria arquivo e adiciona conteudo
        arquivo = saveFileDialog.GetPath()

        file = open(arquivo, "w")

        conteudo = "DA -Firefox Password Recovery - Powered by Desenvolvimento Aberto 2014\n\n" + \
                   "Sistema Operacional: " + self.plataforma() + "\n" + \
                   "Estação: " + socket.gethostname() + "\n" + \
                   "Usuario: " + getpass.getuser() + "\n" + \
                   "Data Extração: " + datetime.datetime.today().strftime('%d-%b-%Y') + "\n\n" + \
                   "Registros encontrados: \n\n"

        for reg in dados:
            conteudo = conteudo + str(reg) + "\n"
        file.write(str(conteudo))
        file.close()
        saveFileDialog.Destroy()

    # Cria evento de saida
    def OnSair(self, evt):
        self.Close(True)

    # Cria evento sobre
    def OnSobre(self, evt):
        # Cria texto para ferramenta
        texto = "Powered by Desenvolvimento Aberto\n\n" + \
                "Autor: Ricardo Mantovani\n" + \
                "E-Mail: desenvolvimento.aberto@live.com\n" + \
                "Blog: http://desenvolvimentoaberto.wordpress.com"
                
        # Cria caixa de texto
        msg = wx.MessageBox(texto, 'Info', wx.OK | wx.ICON_INFORMATION)
        msg.ShowModal()
 
# Inicializa a aplicação
app = wx.App()
frame = Formulario(None)
frame.Show(True)
app.MainLoop()
