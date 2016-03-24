# -*- mode: ruby -*-
# vim: set ft=ruby :

Vagrant.configure(2) do |config|

  #Carteiro
  config.vm.define "carteiro" do |carteiro|
    carteiro.vm.box = "ubuntu/wily64"
    carteiro.vm.hostname = 'carteiro'
    carteiro.vm.network :forwarded_port, host:5000, guest:80
    carteiro.vm.network "private_network", ip: "192.168.0.1"
    carteiro.vm.provision :shell, :path => "static/carteirofiles/install_carteiro.sh"
  end

  #WSUS
  config.vm.define "wsus" do |wsus|
    wsus.vm.box = "kensykora/windows_2012_r2_standard"
    wsus.vm.hostname = 'wsus'
    wsus.vm.network "private_network", ip: "192.168.0.2"
    wsus.vm.provision "shell" do |prov|
      prov.path = "static/winfiles/Install-WSUSServer.ps1"
    end
    # specify to use winrm rather than ssh
    wsus.vm.communicator = "winrm"
    # forward RDP port
    # use "host: 3377" if you are running locally, 
    # since 3389 will be already taken by your RDP listener.
    wsus.vm.network :forwarded_port, guest: 3389, host: 5001
  end

  #Server Client
  config.vm.define "winserver-client" do |wsus|
    wsus.vm.box = "kensykora/windows_2012_r2_standard"
    wsus.vm.hostname = 'testserver'
    wsus.vm.network "private_network", ip: "192.168.0.30"
    wsus.vm.provision "shell" do |prov|
      prov.path = "static/winfiles/Install-WSUSClient.ps1"
    end
    # specify to use winrm rather than ssh
    wsus.vm.communicator = "winrm"
    # forward RDP port
    # use "host: 3377" if you are running locally, 
    # since 3389 will be already taken by your RDP listener.
    wsus.vm.network :forwarded_port, guest: 3389, host: 5010
  end

  #Munki
  config.vm.define "munki" do |munki|
    munki.vm.box = "AndrewDryga/vagrant-box-osx"
    munki.vm.hostname = 'munki'
    munki.vm.network "private_network", ip: "192.168.0.3"
  end

  #Windows Client
  #Password = Passw0rd!
  config.vm.define "win-client" do |winc|
    winc.vm.box = "senglin/win-7-enterprise"
    winc.vm.hostname = "winClient"
    winc.vm.network "private_network", ip: "192.168.0.20"
    # specify to use winrm rather than ssh
    winc.vm.communicator = "winrm"
    # forward RDP port
    # use "host: 3377" if you are running locally, 
    # since 3389 will be already taken by your RDP listener.
    winc.vm.network :forwarded_port, guest: 3389, host: 5002
  end
end
