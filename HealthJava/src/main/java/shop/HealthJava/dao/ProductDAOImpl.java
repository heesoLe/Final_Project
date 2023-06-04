package shop.HealthJava.dao;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import shop.HealthJava.vo.CartVO;
import shop.HealthJava.vo.LikeVO;
import shop.HealthJava.vo.OrderDetailVO;
import shop.HealthJava.vo.ProductVO;
import shop.HealthJava.vo.ProductQnAVO;

@Repository
public class ProductDAOImpl implements ProductDAO {
	
	@Autowired
	private SqlSession sqlSession;

		
	
	@Override
	public ProductVO getProductContent(int product_no) {
		
		return sqlSession.selectOne("product_content",product_no);
	}

	@Override
	public void insertProduct(ProductVO f) {
		
		sqlSession.insert("product_insert",f);
	}

	@Override
	public void deleteProduct(int product_no) {
		sqlSession.delete("product_delete", product_no);
		
	}

	@Override
	public void updateProduct(ProductVO f) {
		sqlSession.update("product_update",f);
		
	}

	
	@Override
	public List<ProductQnAVO> getReviewList(int product_no) {
		return this.sqlSession.selectList("review_list",product_no);
		//selectList()메서드는 복수개의 레코드를 검색해서 컬렉션 List로
		//반환한다. select 아이디명 board_li		
	}//게시판 목록

	@Override
	public void insertQna(ProductQnAVO f) {
		
		this.sqlSession.insert("qna_insert",f);
	}

	@Override
	public void insertLike(LikeVO f) {
		this.sqlSession.insert("like_insert",f);
		
	}

	@Override
	public void deldteLike(LikeVO f) {
		this.sqlSession.insert("like_delete",f);
		
	}

	@Override
	public LikeVO getLikeList(LikeVO f) {
	    
	    
	    return sqlSession.selectOne("like_list",f);
	}

	@Override
	public void insertCart(CartVO c) {
		sqlSession.selectOne("cart_insert",c);
		
	}

	@Override
	public void insertOrderDetail(OrderDetailVO o) {
		sqlSession.insert("orderDetail_insert",o);
		
	}

	@Override
	public List<ProductVO> getListNew(ProductVO f, String kind, String kind2) {
	    System.out.println("f: " + f);
	    System.out.println("kind: " + kind);
	    System.out.println("kind2: " + kind2);
	    System.out.println("검색 필드: " + f.getSearch_field());
	    System.out.println("검색 타입: " + f.getSearch_type());
	    
	    Map<String, Object> paramMap = new HashMap<>();
	    paramMap.put("f", f);
	    paramMap.put("kind", kind);
	    paramMap.put("kind2", kind2);

	    return sqlSession.selectList("new", paramMap);
	}

	@Override
	public int getTotalItems(ProductVO f, String kind, String kind2) {
		Map<String, Object> paramMap = new HashMap<>();
	    paramMap.put("f", f);
	    paramMap.put("kind", kind);
	    paramMap.put("kind2", kind2);
		return sqlSession.selectOne("count", paramMap);
	}
	
}
