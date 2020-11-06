cask "nextcloud" do
  if MacOS.version <= :el_capitan
    version "2.6.5.20200710-legacy"
    sha256 "4c67e50361dd5596fb884002d1ed907fe109d607fba2cabe07e505addd164519"

    # github.com/nextcloud/desktop/ was verified as official when first introduced to the cask
    url "https://github.com/nextcloud/desktop/releases/download/v#{version.major_minor_patch}/Nextcloud-#{version}.pkg"
  else
    version "3.0.3"
    sha256 "272e968cc5f08fab30b58677eadbc7fbd9d28c68d09daadc1869eba90f83d512"

    # github.com/nextcloud/desktop/ was verified as official when first introduced to the cask
    url "https://github.com/nextcloud/desktop/releases/download/v#{version}/Nextcloud-#{version}.pkg"
  end

  appcast "https://github.com/nextcloud/desktop/releases.atom"
  name "Nextcloud"
  desc "Desktop sync client for Nextcloud software products"
  homepage "https://nextcloud.com/"

  depends_on macos: ">= :yosemite"

  pkg "Nextcloud-#{version}.pkg"
  binary "#{appdir}/nextcloud.app/Contents/MacOS/nextcloudcmd"

  uninstall pkgutil: "com.nextcloud.desktopclient"

  zap trash: [
    "~/Library/Application Scripts/com.nextcloud.desktopclient.FinderSyncExt",
    "~/Library/Application Support/Nextcloud",
    "~/Library/Caches/Nextcloud",
    "~/Library/Containers/com.nextcloud.desktopclient.FinderSyncExt",
    "~/Library/Group Containers/com.nextcloud.desktopclient",
    "~/Library/Preferences/com.nextcloud.desktopclient.plist",
    "~/Library/Preferences/Nextcloud",
  ]
end
