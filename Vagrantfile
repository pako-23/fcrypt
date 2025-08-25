
Vagrant.configure('2') do |config|
  $script = <<-SHELL
cd /etc/apt/sources.list.d/
wget http://www.mirbsd.org/~tg/Debs/sources.txt/wtf-bookworm.sources
cd /opt
wget -q -O- https://archive.apache.org/dist/maven/maven-3/3.6.1/binaries/apache-maven-3.6.1-bin.tar.gz | sudo tar -xzv
echo 'export PATH="$PATH:/opt/apache-maven-3.6.1/bin/"' >> /etc/profile
echo 'export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64' >> /etc/profile
apt update
apt-get install -y ca-certificates curl gcc git gnupg make openjdk-8-jdk
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > /tmp/rust-install.sh
chmod +x /tmp/rust-install.sh
/tmp/rust-install.sh -y
SHELL

    config.vm.box = 'debian/bookworm64'
    config.vm.provision :shell, inline: $script, privileged: true

    config.vm.provider 'libvirt' do |v|
      v.memory = 20480
      v.cpus = 10
    end
end
