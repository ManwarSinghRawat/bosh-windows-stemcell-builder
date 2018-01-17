require 'packer/config'

describe Packer::Config::Azure do
  describe 'builders' do
    context 'windows 2016' do
      it 'returns the expected builders' do
        allow(ENV).to receive(:[]).with("BASE_IMAGE_OFFER").and_return("WindowsServer")
        allow(ENV).to receive(:[]).with("BASE_IMAGE").and_return("2016-Datacenter-Server-Core-smalldisk")
        builders = Packer::Config::Azure.new(
          client_id: 'some-client-id',
          client_secret: 'some-client-secret',
          tenant_id: 'some-tenant-id',
          subscription_id: 'some-subscription-id',
          object_id: 'some-object-id',
          resource_group_name: 'some-resource-group-name',
          storage_account: 'some-storage-account',
          location: 'some-location',
          vm_size: 'some-vm-size',
          admin_password: 'some-admin-password',
          output_directory: 'some-output-directory',
          os: 'windows2016'
        ).builders
        expect(builders[0]).to eq(
          'type' => 'azure-arm',
          'client_id' => 'some-client-id',
          'client_secret' => 'some-client-secret',
          'tenant_id' => 'some-tenant-id',
          'subscription_id' => 'some-subscription-id',
          'object_id' => 'some-object-id',

          'resource_group_name' => 'some-resource-group-name',
          'storage_account' => 'some-storage-account',
          'capture_container_name' => 'packer-stemcells',
          'capture_name_prefix' => 'bosh-stemcell',
          'image_publisher' => 'MicrosoftWindowsServer',
          'image_offer' => 'WindowsServer',
          'image_sku' => '2016-Datacenter-Server-Core-smalldisk',
          'location' => 'some-location',
          'vm_size' => 'some-vm-size',
          'os_type' => 'Windows',

          'communicator' => 'winrm',
          'winrm_use_ssl' => 'true',
          'winrm_insecure' => 'true',
          'winrm_timeout' => '1h',
          'winrm_username' => 'packer'
        )
      end
    end
    context 'windows 2012' do
      it 'returns the expected builders' do
        allow(ENV).to receive(:[]).with("BASE_IMAGE_OFFER").and_return("WindowsServer")
        allow(ENV).to receive(:[]).with("BASE_IMAGE").and_return("2012-R2-Datacenter")
        builders = Packer::Config::Azure.new(
          client_id: 'some-client-id',
          client_secret: 'some-client-secret',
          tenant_id: 'some-tenant-id',
          subscription_id: 'some-subscription-id',
          object_id: 'some-object-id',
          resource_group_name: 'some-resource-group-name',
          storage_account: 'some-storage-account',
          location: 'some-location',
          vm_size: 'some-vm-size',
          admin_password: 'some-admin-password',
          output_directory: 'some-output-directory',
          os: 'windows2012R2'
        ).builders
        expect(builders[0]).to eq(
          'type' => 'azure-arm',
          'client_id' => 'some-client-id',
          'client_secret' => 'some-client-secret',
          'tenant_id' => 'some-tenant-id',
          'subscription_id' => 'some-subscription-id',
          'object_id' => 'some-object-id',

          'resource_group_name' => 'some-resource-group-name',
          'storage_account' => 'some-storage-account',
          'capture_container_name' => 'packer-stemcells',
          'capture_name_prefix' => 'bosh-stemcell',
          'image_publisher' => 'MicrosoftWindowsServer',
          'image_offer' => 'WindowsServer',
          'image_sku' => '2012-R2-Datacenter',
          'location' => 'some-location',
          'vm_size' => 'some-vm-size',
          'os_type' => 'Windows',

          'communicator' => 'winrm',
          'winrm_use_ssl' => 'true',
          'winrm_insecure' => 'true',
          'winrm_timeout' => '1h',
          'winrm_username' => 'packer'
        )
      end
    end
  end

  describe 'provisioners' do
    context 'windows 2012' do
      it 'returns the expected provisioners' do
        stemcell_deps_dir = Dir.mktmpdir('azure')
        ENV['STEMCELL_DEPS_DIR'] = stemcell_deps_dir

        allow(SecureRandom).to receive(:hex).and_return("some-password")
        provisioners = Packer::Config::Azure.new(
          client_id: 'some-client-id',
          client_secret: 'some-client-secret',
          tenant_id: 'some-tenant-id',
          subscription_id: 'some-subscription-id',
          object_id: 'some-object-id',
          resource_group_name: 'some-resource-group-name',
          storage_account: 'some-storage-account',
          location: 'some-location',
          vm_size: 'some-vm-size',
          admin_password: 'some-admin-password',
          output_directory: 'some-output-directory',
          os: 'windows2012R2'
        ).provisioners
        expected_provisioners_except_lgpo = [
          {"type"=>"file", "source"=>"build/bosh-psmodules.zip", "destination"=>"C:\\provision\\bosh-psmodules.zip"},
          {"type"=>"powershell", "scripts"=>["scripts/install-bosh-psmodules.ps1"]},
          {'type'=>'powershell', 'inline'=>['$ErrorActionPreference = "Stop";',
                                            'trap { $host.SetShouldExit(1) }',
                                            'Set-ProxySettings   ']},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "New-Provisioner"]},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Install-CFFeatures2012"]},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Add-Account -User Provisioner -Password some-password!"]},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Register-WindowsUpdatesTask"]},
          {"type"=>"windows-restart", "restart_command"=>"powershell.exe -Command Wait-WindowsUpdates -Password some-password! -User Provisioner", "restart_timeout"=>"12h"},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Unregister-WindowsUpdatesTask"]},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Remove-Account -User Provisioner"]},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Test-InstalledUpdates"]},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Protect-CFCell"]},
          {"type"=>"file", "source"=>"../sshd/OpenSSH-Win64.zip", "destination"=>"C:\\provision\\OpenSSH-Win64.zip"},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Install-SSHD -SSHZipFile 'C:\\provision\\OpenSSH-Win64.zip'"]},
          {"type"=>"file", "source"=>"build/agent.zip", "destination"=>"C:\\provision\\agent.zip"},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Install-Agent -IaaS azure -agentZipPath 'C:\\provision\\agent.zip'"]},
          {'type'=>'powershell', 'inline'=> ['$ErrorActionPreference = "Stop";',
                                             'trap { $host.SetShouldExit(1) }',
                                             'Clear-ProxySettings']},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Clear-Provisioner"]},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Invoke-Sysprep -IaaS azure -OsVersion windows2012R2"]}
        ].flatten
        expect(provisioners.detect {|x| x['destination'] == "C:\\windows\\LGPO.exe"}).not_to be_nil
        provisioners_no_lgpo = provisioners.delete_if {|x| x['destination'] == "C:\\windows\\LGPO.exe"}
        expect(provisioners_no_lgpo).to eq (expected_provisioners_except_lgpo)

        FileUtils.rm_rf(stemcell_deps_dir)
        ENV.delete('STEMCELL_DEPS_DIR')
      end
    end
    context 'windows 2016' do
      it 'returns the expected provisioners' do
        stemcell_deps_dir = Dir.mktmpdir('azure')
        ENV['STEMCELL_DEPS_DIR'] = stemcell_deps_dir

        allow(SecureRandom).to receive(:hex).and_return("some-password")
        provisioners = Packer::Config::Azure.new(
          client_id: 'some-client-id',
          client_secret: 'some-client-secret',
          tenant_id: 'some-tenant-id',
          subscription_id: 'some-subscription-id',
          object_id: 'some-object-id',
          resource_group_name: 'some-resource-group-name',
          storage_account: 'some-storage-account',
          location: 'some-location',
          vm_size: 'some-vm-size',
          admin_password: 'some-admin-password',
          output_directory: 'some-output-directory',
          os: 'windows2016'
        ).provisioners
        expected_provisioners_except_lgpo = [
          {"type"=>"file", "source"=>"build/bosh-psmodules.zip", "destination"=>"C:\\provision\\bosh-psmodules.zip"},
          {"type"=>"powershell", "scripts"=>["scripts/install-bosh-psmodules.ps1"]},
          {'type'=>'powershell', 'inline'=>['$ErrorActionPreference = "Stop";',
                                            'trap { $host.SetShouldExit(1) }',
                                            'Set-ProxySettings   ']},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "New-Provisioner"]},
          {"type"=>"windows-restart", "restart_command"=>"powershell.exe -Command Install-CFFeatures2016", "restart_timeout"=>"1h"},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Add-Account -User Provisioner -Password some-password!"]},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Register-WindowsUpdatesTask"]},
          {"type"=>"windows-restart", "restart_command"=>"powershell.exe -Command Wait-WindowsUpdates -Password some-password! -User Provisioner", "restart_timeout"=>"12h"},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Unregister-WindowsUpdatesTask"]},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Remove-Account -User Provisioner"]},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Protect-CFCell"]},
          {"type"=>"file", "source"=>"../sshd/OpenSSH-Win64.zip", "destination"=>"C:\\provision\\OpenSSH-Win64.zip"},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Install-SSHD -SSHZipFile 'C:\\provision\\OpenSSH-Win64.zip'"]},
          {"type"=>"file", "source"=>"build/agent.zip", "destination"=>"C:\\provision\\agent.zip"},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Install-Agent -IaaS azure -agentZipPath 'C:\\provision\\agent.zip'"]},
          {'type'=>'powershell', 'inline'=> ['$ErrorActionPreference = "Stop";',
                                             'trap { $host.SetShouldExit(1) }',
                                             'Clear-ProxySettings']},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Clear-Provisioner"]},
          {"type"=>"powershell", "inline"=>["$ErrorActionPreference = \"Stop\";", "trap { $host.SetShouldExit(1) }", "Invoke-Sysprep -IaaS azure -OsVersion windows2016"]}
        ].flatten
        expect(provisioners.detect {|x| x['destination'] == "C:\\windows\\LGPO.exe"}).not_to be_nil
        provisioners_no_lgpo = provisioners.delete_if {|x| x['destination'] == "C:\\windows\\LGPO.exe"}
        expect(provisioners_no_lgpo).to eq (expected_provisioners_except_lgpo)

        FileUtils.rm_rf(stemcell_deps_dir)
        ENV.delete('STEMCELL_DEPS_DIR')
      end
    end
  end
end
