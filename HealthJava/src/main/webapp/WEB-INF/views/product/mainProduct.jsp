<%@ page contentType="text/html; charset=UTF-8" %>
<%@ taglib prefix="c" uri= "http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous"> <%-- CDN 절대링크 --%>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script> <%-- CDN 절대링크 --%>
<script src="https://code.jquery.com/jquery-3.6.3.js"></script> <%-- CDN 절대링크 --%>
<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script> <%-- CDN 절대링크 --%>
<title>PuppyHome 메인상품페이지</title>

<style type="text/css">
#nodot{
	text-decoration: none !important;
}
@font-face {
		font-family: 'KIMM_Bold';
		src: url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_2212@1.0/KIMM_Bold.woff2') format('woff2'); /* CDN 절대링크  */
		font-weight: 700;
		font-style: normal;
	}
	/* 되도록 안건드리는 영역 */
	* {
		box-sizing: border-box;
		-webkit-box-sizing: border-box;
		-moz-box-sizing: border-box;
	}
	html {
		height: 100%;
	}
	body {
		margin: 0px;
		height: 100%;
		padding: 0px;
	}
	header {
		width: 100%;
	    position: fixed;
		z-index: 2;
	}
	footer {
		bottom: 0;
		z-index: 5;
		position: relative;
	}
	.wrap {
		margin-top: -110px;
		min-height: 100%;
	    position: relative;
	}
	.main { 
		width: 1400px;
		height: 2000px; /* UI 개발할 때 각 페이지에 맡게 해당 영역 px수치 수정해야함 / section이랑 px 맞춰야함 */
		position : relative;
		top: 105px;
		left: 50%;
        transform: translateX( -50% );
		
	}
	section {
		height: 2000px; /* UI 개발할 때 각 페이지에 맡게 해당 영역 px수치 수정해야함 / .main이랑 px 맞춰야함 */
		
	}
	/* 클리어 */
	.clear {
		clear: both;
	}
	/* 밑의 영역부터 css시작 */
	.container {
		width: 100%;
	}
	/* 캐러셀 */
	#carouselExampleControls {
		width: 1100px;
		position : relative;
		left: 50%;
        transform: translateX( -50% );
	}
	
	
	/*본문 css 시작*/
	
	.product_item{
	font-family: 'KIMM_Bold';
	}
	
	.product_list list>li{
	--vh: 8.68px;
    word-wrap: break-word;
    word-break: keep-all;
    color: #000000;
    line-height: 1.6;
    -webkit-text-size-adjust: none;
    letter-spacing: -0.2px;
    font-family: 'KIMM_Bold';
    -webkit-tap-highlight-color: transparent;
    box-sizing: border-box;
    outline: none !important;
    margin: 0;
    border: 0;
    max-height: 1000000px;
    font-size: 100%;
    font-weight: normal;
    display: flex;
    align-items: flex-end;
    gap: 10px;
    position: relative;
    padding: 0;
}

.product_list list>li>span{
    --vh: 8.68px;
    word-wrap: break-word;
    word-break: keep-all;
    -webkit-text-size-adjust: none;
    font-family: 'KIMM_Bold';
    -webkit-tap-highlight-color: transparent;
    box-sizing: border-box;
    outline: none !important;
    margin: 0;
    padding: 0;
    border: 0;
    max-height: 1000000px;
    display: block;
    line-height: 25px;
    font-size: 20px;
    color: #000;
    font-weight: 700;
    letter-spacing: -.3px;
}

.product_list list>li>button{
    --vh: 8.68px;
    word-wrap: break-word;
    word-break: keep-all;
    -webkit-text-size-adjust: none;
    box-sizing: border-box;
    outline: none !important;
    max-height: 1000000px;
    letter-spacing: -0.2px;
    font-family:'KIMM_Bold';
    vertical-align: middle;
    -webkit-tap-highlight-color: transparent;
    cursor: pointer;
    background: none;
    border: none;
    position: absolute;
    top: 0;
    right: 0;
    height: 25px;
    line-height: 25px;
    font-size: 15px;
    color: #000;
    font-weight: bold;
    padding: 0 20px 0 5px;
}
.product_rating {
  float: right;
  width: 100px;
  height: 20px;
  overflow: hidden;
  background: url(https://bit.ly/1B4PjyM) top left no-repeat;
  background-position: 0 76%;
}	
	
	
ul.product_list {
  display: block;
  float: left;
  list-style-type: none;
  margin: 0;
  padding: 0;
  width: 100%;
}
.product_grid a {
  text-decoration: none;
}
.product_item {
  display: inline-block;
  background: #fff;
  border: 1px solid #ccc;
  padding: 10px;
  position: relative;
  border-radius: 15px;
}

.product_image {
  position: relative;
  overflow: hidden;
  border-radius: 10px;
}
.product_image a {
  display: block;
}
.product_image img {
  display: block;
  -webkit-transition: all .35s ease-in-out;
  -moz-transition: all .35s ease-in-out;
  transition: all .35s ease-in-out;
}
.product_image img:hover {
  -o-transform: scale(1.2, 1.2);
  -moz-transform: scale(1.2, 1.2);
  -webkit-transform: scale(1.2, 1.2);
  -ms-transform: scale(1.2, 1.2);
  transform: scale(1.2, 1.2);
}
.product_image:hover .product_buttons {
  bottom: 0;
}
.product_buttons {
  position: absolute;
  bottom: -40%;
  left: 0;
  width: 100%;
  text-align: center;
  -webkit-transition: all .35s ease;
  -moz-transition: all .35s ease;
  transition: all .35s ease;
}
.product_buttons button {
  color: #fff;
  border: none;
  background: rgba(0, 0, 0, 0.5);
  font-size: 1em;
  border-radius: 50%;
  width: 40px;
  height: 40px;
}
.product_buttons .product_heart:hover {
  color: white;
  background: red;
}

.product_title {
  float: left;
  width: 100%;
  text-transform: uppercase;
}

.goods_title {
  color: black;
}

.goods_title:hover {
  color: #ea2e49;
}

.product_price a {
  color: #000;
}
.price_old {
  color: #ea2e49;
  text-decoration: line-through;
}

.price_new {
  color: black;
}

.price_new:hover {
  color: #ea2e49;
}


/*==========  Mobile First Method  ==========*/

/* Custom, iPhone Retina */ 
@media only screen and (min-width : 320px) {
  ul.product_list {
    margin: 0;
  }
  .product_item {
    width: 100%;
    margin: 0;
    overflow: hidden;
  }
  .product_sale {
    position: absolute;
    z-index: 99;
    right: -28px;
    -webkit-transform: rotate(45deg);
    -moz-transform: rotate(45deg);
    transform: rotate(45deg);
  }
  .product_sale p {
    margin: 0;
    color: #fff;
    background: #ff0000;
    padding: 3px 25px;
    box-shadow: 0 2px 8px 0 rgba(0, 0, 0, 0.4);
  }
  .product_image {
    height: 150px;
    float: left;
    width: 100px;
  }
  .product_image .product_buttons {
    display: none;
  }
  .product_title h5 {
    margin: auto;
    font-size: 1em;
    font-weight: 500;
    line-height: 1;
  }
  .product_price span {
    font-size: 1.1em;
    line-height: 1;
  }

  .product_values .product_buttons {
    position: relative;
    text-align: left;
    float: left;
    margin-top: 7px;
  }
  .product_values .product_buttons button {
    color: #252525;
    background: rgba(255, 255, 255, 1);
    font-size: 1em;
    border-radius: 50%;
    width: 40px;
    height: 40px;
    border: 1px solid #000;
  }
}

/* Extra Small Devices, Phones */ 
@media only screen and (min-width : 480px) {
  ul.product_list {
    margin: 1%;
  }
  .product_item {
    width: 49%;
    margin: 0;
  }
  .product_image {
    height: 300px;
    float: left;
    width: 100%;
    text-align: center;
  }
  .product_image img {
    max-height: 100%;
    display: inline-block;
  }
  .product_title h5 {
    font-size: 1.1em;
    font-weight: 500;
    line-height: 1;
    padding: 10px 0 0;
    text-align: center;
}
  .product_image .product_buttons {
    display: block;
  }
  .product_price {
    float: left;
    text-align: center;
    width: 100%;
  }
  
  
  .product_rating {
    width: 100%;
    background-position: center 76%;
    margin-bottom: 5px;
  }
  
  
  .product_values .product_buttons {
    display: none;
  }
}

@media only screen and (min-width: 678px) {
  .product_item {
    width: 32.5%;
  }
}

/* Small Devices, Tablets */
@media only screen and (min-width : 768px) {

}

/* Medium Devices, Desktops */
@media only screen and (min-width : 992px) {
  .product_item {
    width: 24.25%;
  }
}

/* Large Devices, Wide Screens */
@media only screen and (min-width : 1200px) {
  .product_item {
    width: 19.5%;
  }
}



/*==========  Non-Mobile First Method  ==========*/

/* Large Devices, Wide Screens */
@media only screen and (max-width : 1200px) {

}

/* Medium Devices, Desktops */
@media only screen and (max-width : 992px) {
  
}

/* Small Devices, Tablets */
@media only screen and (max-width : 768px) {

}

/* Extra Small Devices, Phones */ 
@media only screen and (max-width : 480px) {
  .product_title h5 {
    font-weight: bold;
  }
 .product_values {
    float: left;
    width: calc(100% - 100px);
    padding: 0 10px;
  }

  .product_image {
    height: 150px;
    float: left;
    width: 100px;
  }
  .product_image .product_buttons {
    display: none;
  }
  .product_values .product_buttons {
    position: relative;
    text-align: left;
    float: left;
    margin-top: 7px;
  }
  .product_values .product_buttons button {
    color: #252525;
    background: rgba(255, 255, 255, 1);
    font-size: 1em;
    border-radius: 50%;
    width: 40px;
    height: 40px;
    border: 1px solid #000;
  }  
}

/* Custom, iPhone Retina */ 
@media only screen and (max-width : 320px) {
   .product_sale {
    display: none;
  }
  .product_image {
    height: auto;
    width: 100%;
  }
  .product_image .product_buttons {
    display: block;
  }
  .product_values {
    width: 100%;
    padding: 0;
    margin: 5px 0;
  }
  .product_title h5 {
    margin: auto;
    font-size: 1em;
    line-height: 1;
    font-weight: bold;
  }
  .product_values .product_buttons {
    display: none;
  }
}	
</style>
<script>
function checkWindowSize() {
    if ( jQuery(window).width() >= 480 ) {
        $('.truncate').succinct({
            size: 100
        }); 
    }
    else if ( jQuery(window).width() >= 320 ) {
        $('.truncate').succinct({
            size: 55
        }); 
    } 
    else {
        $('.truncate').succinct({
            size: 150
        }); 
    }   
}

jQuery(document).ready(function(){
    jQuery(window).resize(checkWindowSize);
    checkWindowSize();
});
</script>

</head>
</style>
</head>
<body>
	<%-- 전체 영역 --%>
	<div class="wrap">
		<%-- 헤더 영역 --%>
		<header>
			<%-- header include --%>
			<jsp:include page="../include/header.jsp"/>
		</header>
		<%-- 본문 영역(ui깨질시 본인이 ui 수정바람..) --%>
		<section>
			<div class="main">
				<div class="container">
					<%-- main 화면 상단 캐러셀 (캐러셀 필요 없는 페이지는 삭제 바람!)--%>
						<div id="carouselExampleControls" class="carousel slide" data-bs-ride="carousel" data-bs-interval="2500">
						  <div class="carousel-inner">
						    <div class="carousel-item active">
						      <img src="<%=request.getContextPath()%>/images/main_banner02.jpg" class="d-block w-100" alt="...">
						    </div>
						    <div class="carousel-item">
						      <img src="<%=request.getContextPath()%>/images/main_banner03.jpg" class="d-block w-100" alt="...">
						    </div>
						    <div class="carousel-item">
						      <img src="<%=request.getContextPath()%>/images/main_banner04.jpg" class="d-block w-100" alt="...">
						    </div>
						   
						   
						  </div>
						  <button class="carousel-control-prev" type="button" data-bs-target="#carouselExampleControls" data-bs-slide="prev">
						    <span class="carousel-control-prev-icon" aria-hidden="true"></span>
						    <span class="visually-hidden">Previous</span>
						  </button>
						  <button class="carousel-control-next" type="button" data-bs-target="#carouselExampleControls" data-bs-slide="next">
						    <span class="carousel-control-next-icon" aria-hidden="true"></span>
						    <span class="visually-hidden">Next</span>
						  </button>
						</div>
					<%-- 캐러셀 끝 이 밑으로 작성!--%>
					
<%-- 본문시작 --%>

<br><br>

<div class="product_grid">
  
  <iframe width="1000" height="800" src="https://www.youtube.com/embed/IjEzWlyWM0U?autoplay=1" frameborder="0" allow="autoplay; encrypted-media" allowfullscreen></iframe>
  
</div>
<br><br>
<div >
	<img src="<%=request.getContextPath()%>/images/154647.jpg" width = "1000px" height = "500px" alt="...">
</div>


				</div>
			</div>
	
			<%-- top버튼 삭제 X --%>
			<div id="topBtn">
				<span class="fonti um-arrow-circle-up um-3x icon"></span>TOP
			</div>
		</section>
	<%-- 푸터 영역 --%>
	<footer>
		<!-- footer -->
		<jsp:include page="../include/footer.jsp"/>
		<!-- footer 끝 -->
	</footer>
	</div>
	<script type="text/javascript">
	
		<%-- top버튼 부분 --%>
		// 클릭 이벤트 핸들러
		$("#topBtn").click(function(e) {
			e.stopPropagation();
			$("html, body").animate({
				scrollTop : 0
			}, 'fast', 'easeOutCubic');
		});

		// 스크롤 이벤트 핸들러
		$(window).scroll(function() {
			if ($(window).scrollTop() == 0) {
				$("#topBtn").css("opacity", 0); // TOP 버튼 숨기기
			} else {
				$("#topBtn").css("opacity", 1); // TOP 버튼 나타내기
			}
		});
	</script>
</body>
</html>