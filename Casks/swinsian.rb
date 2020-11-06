cask "swinsian" do
  version "2.3.2"
  sha256 "190a382c96253e8e596b1df942fd762dc8307c6bdf2fc2c1a331b62c65ac63c6"

  url "https://www.swinsian.com/sparkle/Swinsian_#{version}.zip"
  appcast "https://www.swinsian.com/sparkle/sparklecast.xml"
  name "Swinsian"
  homepage "https://swinsian.com/"

  auto_updates true

  app "Swinsian.app"
end
