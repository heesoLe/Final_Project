//주문내역 검색
function Order_search(){
	  var adminTab = $('#adminTab5').attr('value');
	  console.log(adminTab);
   $.ajax({//$는 jQuery란 뜻. $.ajax 뜻은 jQuery 내의 아작스 실행
      url:"/admin_list", //url 패턴 매핑주소 경로
      type:"POST",//데이터를 서버로 보내는 방법
      data: {
        "adminTab" : adminTab
      },  //좌측 id 피라미터 이름에 우측 $mem_id변수값을 저장
      datatype: "json",//서버의 실행된 결과값을 사용자로 받아오는 자료형
		traditional : true,
      success: function (res) {	
		var olist = res.olist;
 		$('#ajaxHead').empty();
 		$('#ajaxTh').empty();
 		$('#ajaxTable').empty();
 		$('#ajaxhome').empty();
        var OrderCountHtml = "<div align='right' style='margin-bottom:20px;'>총 주문 수: " + res.order_counts + "개</div>";
        $('#ajaxHead').append(OrderCountHtml);
          
          var table_head = `
          <h3 align="center">&nbsp;주문&nbsp내역 관리</h3>
         <br>
          <p>
          <p>
          `
          $('#ajaxHead').append(table_head);
          
          $('#ajaxTh').empty();
          
          var table_th = `
					<tr>
						<th width="100">주문번호</th>
            			<th width="100">주문자</th>
						<th width="100">제품명</th>
						<th width="200">주문일자</th>
						<th width="100">주문수량</th>
						<th width="200">송장번호</th>
						<th width="200">합계</th>
			            <th width="200">주문상태</th>
						<th width="200">비고</th>
					</tr>
        `;

        $('#ajaxTh').append(table_th);
        
		$('#ajaxTable').empty();
		
function numberWithCommas(x) {
  return x.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}
		 for(let i = 0; i < olist.length; i++){
		 var orderInvoice = olist[i].order_invoice;
			 const html = `
				<tr>
  					<td>${olist[i].order_no}</td>
       			    <td>${olist[i].user_id}</td>
			  		<td><a onclick="Order_Detail(${olist[i].order_no})" style="cursor:pointer; color:#0d6efd;">${olist[i].order_product_title}</a></td>
       				<td>${olist[i].order_date.substring(0,10) }</td>
				 	<td>${olist[i].order_cnt }개</td>
         			<td>${olist[i].order_invoice }</td>
			  		<td>${numberWithCommas(olist[i].order_total)}원</td>
      				 ${orderInvoice !== ' ' ? '<td>배송완료</td>' : '<td>대기</td>'}
      			    <td><input id="btn" type="button" value="송장번호 입력" onclick="Order_Invoice(${olist[i].order_no});"/></td> 
		    	</tr>
			 `
             //통신 성공시 탭 내용담는 div를 읽어들인 값으로 채운다.
             $('#ajaxTable').append(html); 
  		 }
	  }
    });//$.ajax

}


//주문 상세내역
function Order_Detail(order_no){
	
  $.ajax({
      url:"/order_detail", //url 패턴 매핑주소 경로
      type:"post",//데이터를 서버로 보내는 방법
      data: {
      	"order_no" : order_no
      },  //좌측 id 피라미터 이름에 우측 $mem_id변수값을 저장
      datatype: "json",
		traditional : true,
      success: function (res) {	
 		$('#ajaxHead').empty();
 		$('#ajaxTh').empty();
 		$('#ajaxTable').empty();
 		$('#ajaxhome').empty();
 		 var home = "<input id='btn' type='button' value='목록보기' style='margin-bottom:20px;' onclick='Order_search();' />";
        $('#ajaxhome').append(home);
        
          var table_head = `
          <h3 align="center">&nbsp;주문상세 내역 </h3>
         <br>
          <p>
          <p>
          `
          $('#ajaxHead').append(table_head);
          
          $('#ajaxTh').empty();
          
          var table_th = `
					<tr>
						<th width="200">주문번호</th>
						<th width="200">제품명</th>
						<th width="200">판매가</th>
						<th width="200">주문수량</th>
						<th width="200">합계</th>
					</tr>
        `;

        $('#ajaxTh').append(table_th);
        
		$('#ajaxTable').empty();
		
		function numberWithCommas(x) {
  		return x.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
		}
		
		 for(let i = 0; i < res.length; i++){
			 const html = `
				<tr>
  					 <td>${res[i].order_no}</td>
         			 <td>${res[i].order_detail_pname}</td>
			     	 <td>${numberWithCommas(res[i].order_detail_price)}원</td>
       	 			 <td>${res[i].order_detail_cnt }</td>
        			 <td>${numberWithCommas(res[i].order_detail_cnt * res[i].order_detail_price)}원</td>
				 </tr>
				

			 `
             //통신 성공시 탭 내용담는 div를 읽어들인 값으로 채운다.
             $('#ajaxTable').append(html); 
  		 }
	  }
    });//$.ajax
};

//송장번호 입력
function Order_Invoice(order_no){
	
  $.ajax({
      url:"/order_invoice", //url 패턴 매핑주소 경로
      type:"post",//데이터를 서버로 보내는 방법
      data: {
      	"order_no" : order_no
      },  //좌측 id 피라미터 이름에 우측 $mem_id변수값을 저장
      datatype: "json",
		traditional : true,
      success: function (res) {	
 		$('#ajaxHead').empty();
 		$('#ajaxTh').empty();
 		$('#ajaxTable').empty();
		$('#ajaxhome').empty();
		
        var table_head = `
					<table class="memList" align="center">
					<tr> 
						<th class="th-list">주문&nbsp;번호&nbsp; </th>
						<td class="td-inputInfo"> 
							<input type="text" name="order_no" id="order_no" value="${res.order_no}" size="70">
					</tr>

					<tr>
						<th rowspan="2" class="th-list">상&nbsp;품&nbsp;명</th>
						<td class="td-inputInfo">
							<input type="text" name="order_product_title" id="order_product_title" value="${res.order_product_title}" size="70">
						</td>
						
					</tr>			
					<tr>
						<td class="td-infoPs"></td> 
					</tr>

					<tr>
						<th rowspan="2" class="th-list" >송&nbsp;장&nbsp;번&nbsp;호</th>
						<td class="td-inputInfo"> 
							<input type="text" name="order_invoice" id="order_invoice" size="70">
						</td>
					<tr>
						<td class="td-infoPs"></td>
					</tr>

				</table><br><br>
        	<input id="btn" type="button" value="수정" onclick="return Invoice_check();" />
				 &nbsp;					
				 <input id="btn" type="button" value="목록보기" onclick="Order_search();" />
          `
          $('#ajaxHead').append(table_head);
	  }
    });//$.ajax
};

//송장번호 입력 ok
function Order_Invoice_ok(){

	
  $.ajax({
      url:"/order_invoice_ok", //url 패턴 매핑주소 경로
      type:"post",//데이터를 서버로 보내는 방법
      data: {
      	"order_invoice" : $('#order_invoice').val()
      	, "order_no" : $('#order_no').val()
      },  //좌측 id 피라미터 이름에 우측 $mem_id변수값을 저장
      datatype: "json",
		traditional : true,
      success: function (res) {
      	alert('송장번호 입력 성공');
		    Order_search();

	  }
    });//$.ajax
};

	function Invoice_check() {
		var answer;
		answer=confirm("송장번호를 입력하시겠습니까?");
							
		if(answer == true){
			Order_Invoice_ok();
			return true;
		} else if (answer == false){
			return false;
		}
	}