cask "icefloor" do
  version "2.0.2"
  sha256 "b326bab20c022c12be9ed01c3aa0e5f072853ce7dc5fb756bddebc2c3abddf64"

  url "https://www.hanynet.com/icefloor-#{version}.zip"
  appcast "https://www.hanynet.com/icefloor/"
  name "IceFloor"
  homepage "https://www.hanynet.com/icefloor/"

  app "IceFloor.app"
end
