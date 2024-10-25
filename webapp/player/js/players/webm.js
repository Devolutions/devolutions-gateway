/**
 * Handles the playback of WebM videos using the provided gateway API.
 *
 * @param {GatewayAccessApi} gatewayApi - The API to access the gateway for video streaming.
 */
export function handleWebm(gatewayApi) {
  const videoPlayer = document.createElement('video');
  videoPlayer.id = 'videoPlayer';
  videoPlayer.controls = true;
  videoPlayer.autoplay = true;
  videoPlayer.name = 'media';
  videoPlayer.muted = true;

  const videoSrcElement = document.createElement('source');
  videoSrcElement.id = 'videoSrcElement';
  videoSrcElement.type = 'video/webm';

  videoPlayer.appendChild(videoSrcElement);
  document.body.appendChild(videoPlayer);

  let currentIndex = 0;
  const { recordingInfo } = gatewayApi.info();
  const maxIndex = recordingInfo.files.length - 1;

  const setVideoSource = (index) => {
    const videoSrc = gatewayApi.staticRecordingUrl(recordingInfo.files[index].fileName);
    videoSrcElement.setAttribute('src', videoSrc);
    videoPlayer.load();
    videoPlayer.play();
  };

  setVideoSource(currentIndex);

  videoPlayer.onended = () => {
    currentIndex = (currentIndex + 1) % (maxIndex + 1);
    setVideoSource(currentIndex);
  };
}
