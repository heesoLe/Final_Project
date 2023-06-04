<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>

<head>
 <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
 <jsp:include page="../include/header.jsp"/>
 <link rel="shortcut icon" href="<%=request.getContextPath()%>/images/favicon.ico" type="image/x-icon"> <%-- 파비콘 --%>
<link rel="stylesheet" href="<%=request.getContextPath()%>/css/customer_center.css">
<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/page/include/css/header.css"> <%-- header.css --%>
<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/page/include/css/footer.css"> <%-- footer.css --%>
<%-- <script type="text/javascript" src="<%=request.getContextPath()%>/js/jquery.js"></script> --%>
<script src="<%=request.getContextPath()%>/js/cs.js"></script>
  <script src="https://code.jquery.com/jquery-3.6.3.js" integrity="sha256-nQLuAZGRRcILA+6dMBOvcRh5Pe310sBpanc6+QBmyVM=" crossorigin="anonymous"></script>
   <meta name="viewport" content="width=device-width, initial-scale=1">
  <!-- <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"> -->
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.16.0/umd/popper.min.js"></script>
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
  
<!-- 서머노트를 위해 추가해야할 부분 -->
 <%--  <script src="${pageContext.request.contextPath}/resources/summernote/summernote-lite.min.js"></script>
  <script src="${pageContext.request.contextPath}/resources/summernote/lang/summernote-ko-KR.min.js"></script>
  <link rel="stylesheet" href="${pageContext.request.contextPath}/resources/summernote/summernote-lite.min.css"> --%>
  <!--  -->
<link href="https://cdn.jsdelivr.net/npm/summernote@0.8.18/dist/summernote-lite.min.css" rel="stylesheet"> 
  <script src="https://cdn.jsdelivr.net/npm/summernote@0.8.18/dist/summernote-lite.min.js"></script>
  <script src=" https://cdnjs.cloudflare.com/ajax/libs//0.8.18/lang/summernote-ko-KR.min.js"></script> 
<title>Insert title here</title>

<style>
.inquire-notice-div{
    padding-top: 20px;
	position:relative;
	left:17%;
	ont-size: unset;
	font-family: 'KIMM_Bold';
	margin: unset;
    height: 120px;
    width: 1400px;
}
.inquire-table-div{
	width: 90%;
  	max-width: 800px;
  	padding: 40px 20px;
  	border: 2px solid #b21949;
  	border-radius: 16px;
  	margin: 20px auto;
  	font-family: 'KIMM_Bold';
}
#label_h3{
	font-size: 30px;
	background-color:white;
	position : relative;
	left:17%;
	top:25px;
	font-family: 'KIMM_Bold';
	margin: unset;
    height: 40px;
    width: 1400px;
}

ul{
	list-style-type: none;

}

#notice1{
	color: #b21949;
	font-family: 'KIMM_Bold';
}
hr{
	border: 3px;
 	height: 2px; /* hr 높이 설정 */
 	background-color: #b21949; /* hr 색상 설정 */
 	margin: 25px 10px; /* hr 위아래 간격 설정 */
}
p{
	font-size: medium;
	background-color:white;
}
#texts{
	width: 100%;
	max-width:600px;
	height:150px;
	resize: none;
}

#button1 {
  font-size: 0.9rem;
  letter-spacing: -.02rem;
  width: 150px;
  margin: 0 auto;
  padding: .6rem;
  border: 1px solid rgba(0, 0, 0, 0.2);
  border-radius: 4px;
  transition: 0.1s;
  cursor: pointer;
  font-family: 'KIMM_Bold';
  background: #b21949;
  color: white;
}

.summernote{
	height: 200px;
	width: 600px;
}

#button1:hover {
  border: 1px solid rgba(0, 0, 0, 0.3);
}

.btn-default {
  background: #f6f6f6;
  color: #111;
  background: #eee;
}

.btn-default:hover {
  background: #e1e1e1;
}

.btn-rank2 {
  background: #444;
  color: #fff;
}

.btn-rank2:hover {
  background: #222;
}

.flex-box {
  width: 100%;
  display: flex;
  flex-direction: row;
  gap: 10px;
  align-items: center;
  vertical-align: middle;
}

.file-box {
  position: relative;
  display: inline-block;
}

.file-box label {
  display: inline-block;
  padding: 10px 20px;
  color: #999;
  background: #eee;
  cursor: pointer;
  border: 1px solid #ddd;
  border-radius: 4px;
  transition: all 0.2s;
}

.file-box label:hover {
  color: #999;
  background: #e4e4e4;
  border: 1px solid #d4d4d4;
}

.file-box input[type="file"] {
  position: absolute;
  width: 0;
  height: 0;
  padding: 0;
  overflow: hidden;
  border: 0;
}

.inquire-table{
	border-spacing: 10px;
	border-collapse: separate;
	align: center;
}

input[type="text"] {
  width: 100%;
  max-width: 600px;
  font-family: 'KIMM_Bold';
}

input[type="password"] {
  font-family: 'serif';
}

#inquire_select{
	width:100%;
	max-width:600px;
	font-family: 'KIMM_Bold';
}

</style>
<script type="text/javascript">
var a;
function change_category(a){
	$('#client_category').val(a);	
}
</script>
</head>
<section class="notice">

<div>
 <ul id="cs_faq_list">
  <li><a href="notice.jsp">공지사항</a></li>
  <li><a href="FAQ.jsp">FAQ</a></li>
  <li><a href="contact.jsp">1:1문의</a></li>
 </ul>
 <hr id="label_hr">
</div>

<br>
<p id="label_h3">1:1 Q&A</p>

<div class="inquire-notice-div">

 <ul id="inquire_notice_list">
  <li><a id="notice1">- 안내사항 입니다. 제품사용, 오염, 전용박스 손상등 교환/환불 불가합니다.</a></li>
  <li><a id="notice1">- 교환을 원하는 상품의 재고가 부족 시, 교환 불가합니다.</a></li>
  <li><a>- 고객의 주문내역을 선택, 질문이 필요한 상품을 선택하시면 1:1상담이 가능합니다.</a></li>
  <li><a>- 주문 취소/교환/환불은 <strong id="inquiremypage">마이페이지>주문내역</strong>에서 확인할수 있습니다.</a></li>
  <li><a>- 안내사항 입니다.</a></li>
 </ul>
</div>
<br>   
  <!-- 문의 작성 폼 -->
  <p id="label_h3">문의 작성</p>
  <hr>
  <br>
  
  <div class="inquire-table-div">
  <form action="contact_write_ok" method="post" onsubmit="return write_check();">
   <table class="inquire-table">
    <tr>
     <th rowspan="4" align="center">문의 유형</th>
     <td>
     	<input id="button1" type="button" value="로그인/정보" onclick="change_category('로그인/정보');">
       	<button id="button1" type="button" onclick="change_category('주문/결제');">주문/결제</button>
       	  <button id="button1" type="button" onclick="change_category('배송문의');">배송문의</button>
     	<button id="button1" type="button" onclick="change_category('교환/취소(반품)');">교환/취소(반품)</button>
     </td>
    </tr>



    <tr>
    <td><input type="text" id="client_category" name="client_category" value="문의 유형을 선택해 주세요."></td>
    </tr>
    	
	<tr></tr><tr></tr>
     
    <tr>
     <th rowspan="2" align="center">작성자</th>
     <td><input type="text" name="user_id" value="${session_id}" readonly="readonly" style="background-color: lightgray;"></td>
    </tr>
	<tr></tr>

    <tr>
     <th rowspan="2" align="center">글 비밀번호</th>
     <td><input type="password" name="contact_password" size="50" placeholder="글 조회에 필요한 비밀번호를 입력해주세요"></td>
    </tr>
	<tr></tr>

    <tr>
    <th rowspan="2" align="center">제목</th>
    <td><input type="text" class="rag-title" name="reg-title" placeholder="제목을 입력하세요"></td>
    </tr>
	<tr></tr>
	    
    <tr>
     <th rowspan="5" align="center">문의내용</th>
     <td>
       <!-- <textarea placeholder="문의내용을 입력해주세요." maxlength="2000" rows="6" id="texts" spellcheck="false"></textarea> -->
        <textarea id="summernote" class="summernote" name="editordata"></textarea>      
     </td>
    </tr>
	<tr></tr><tr></tr><tr></tr><tr></tr><tr></tr>
	
    <tr>
    <th></th>
    <td>
    <div class="flex-box">
        <button id="button1" class="btn-rank2">등록하기</button>
        <button type="reset" id="button1" class="btn-default" onclick="location='contact';">취소</button> 
      </div>
    </td>
    </tr>
   
   </table>
  	
  </form>
  </div>
  <script>
/* $('.summernote').summernote({
	height: 300,                 // 에디터 높이
	//width:400,					
	  minHeight: null,             // 최소 높이
	  maxHeight: null,             // 최대 높이
	  focus: true,                  // 에디터 로딩후 포커스를 맞출지 여부
	  //lang: "ko-KR",					// 한글 설정
	  placeholder: '최대 2048자까지 쓸 수 있습니다'	,//placeholder 설정
	  
		 toolbar: [
			    // [groupName, [list of button]]
			    ['fontname', ['fontname']],
			    ['fontsize', ['fontsize']],
			    ['style', ['bold', 'italic', 'underline','strikethrough', 'clear']],
			    ['color', ['color']],
			    //['table', ['table']],
			    //['para', ['ul', 'ol', 'paragraph']],
			    ['height', ['height']],
			    ['insert',['picture','link']],
			    ['view', ['fullscreen', 'help']]
			  ],
			fontNames: ['Arial', 'Arial Black', 'Comic Sans MS', 'Courier New','맑은 고딕','궁서','굴림체','굴림','돋움체','바탕체'],
			fontSizes: ['8','9','10','11','12','14','16','18','20','22','24','28','30','36','50','72'] 
	});
 */
 
<%-- $('.summernote').summernote({
	  toolbar: [
	    // [groupName, [list of button]]
	    ['style', ['bold', 'italic', 'underline', 'clear']],
	    ['fontsize', ['fontsize']],
	    ['color', ['color']],
	    ['para', ['ul', 'ol', 'paragraph']],
	    ['height', ['height']]
	  ],
	  height: 200,
	  minHeight: null,
	  maxHeight: null,
	  focus: false,
	  lang: "ko-KR",
	  placeholder: '문의내용을 입력해주세요. \n최대 2048자까지 쓸 수 있습니다'
	});--%>
	

</script>
  
</section>
<script>

function write_check() {
	var answer;
	answer=confirm("문의글을 등록 하시겠습니까?");
						
	if(answer == true){
		alert('글 등록에 성공했습니다.');
		return true;
	} else if (answer == false){
		return false;
	}
}

</script>

		<%-- 푸터 영역 --%>
			<footer>
	<!-- footer -->
	<jsp:include page="../include/footer.jsp"/>
	</footer>
