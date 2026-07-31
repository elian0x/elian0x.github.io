document.addEventListener('DOMContentLoaded', function () {
  var root = document.getElementById('home-carousel');
  if (!root) return;

  var track = root.querySelector('.carousel-track');
  var slides = root.querySelectorAll('.carousel-slide');
  var prevBtn = root.querySelector('.carousel-prev');
  var nextBtn = root.querySelector('.carousel-next');
  var dots = root.querySelectorAll('.carousel-dot');
  var count = slides.length;
  var index = 0;

  if (count <= 1) return;

  function render() {
    track.style.transform = 'translateX(-' + index * 100 + '%)';
    dots.forEach(function (dot, i) {
      dot.classList.toggle('active', i === index);
    });
  }

  function go(delta) {
    index = (index + delta + count) % count;
    render();
  }

  prevBtn.addEventListener('click', function () {
    go(-1);
  });

  nextBtn.addEventListener('click', function () {
    go(1);
  });

  dots.forEach(function (dot, i) {
    dot.addEventListener('click', function () {
      index = i;
      render();
    });
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'ArrowLeft') go(-1);
    if (e.key === 'ArrowRight') go(1);
  });

  var startX = null;

  root.addEventListener(
    'touchstart',
    function (e) {
      startX = e.touches[0].clientX;
    },
    { passive: true }
  );

  root.addEventListener('touchend', function (e) {
    if (startX === null) return;
    var deltaX = e.changedTouches[0].clientX - startX;
    if (Math.abs(deltaX) > 50) {
      go(deltaX > 0 ? -1 : 1);
    }
    startX = null;
  });

  render();
});
