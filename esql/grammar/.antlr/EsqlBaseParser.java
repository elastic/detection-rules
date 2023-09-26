// Generated from /Users/tdejesus/code/src/detection-rules/esql/grammar/EsqlBaseParser.g4 by ANTLR 4.9.2
import org.antlr.v4.runtime.atn.*;
import org.antlr.v4.runtime.dfa.DFA;
import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.misc.*;
import org.antlr.v4.runtime.tree.*;
import java.util.List;
import java.util.Iterator;
import java.util.ArrayList;

@SuppressWarnings({"all", "warnings", "unchecked", "unused", "cast"})
public class EsqlBaseParser extends Parser {
	static { RuntimeMetaData.checkVersion("4.9.2", RuntimeMetaData.VERSION); }

	protected static final DFA[] _decisionToDFA;
	protected static final PredictionContextCache _sharedContextCache =
		new PredictionContextCache();
	public static final int
		DISSECT=1, DROP=2, ENRICH=3, EVAL=4, EXPLAIN=5, FROM=6, GROK=7, INLINESTATS=8, 
		KEEP=9, LIMIT=10, MV_EXPAND=11, PROJECT=12, RENAME=13, ROW=14, SHOW=15, 
		SORT=16, STATS=17, WHERE=18, UNKNOWN_CMD=19, LINE_COMMENT=20, MULTILINE_COMMENT=21, 
		WS=22, EXPLAIN_WS=23, EXPLAIN_LINE_COMMENT=24, EXPLAIN_MULTILINE_COMMENT=25, 
		PIPE=26, STRING=27, INTEGER_LITERAL=28, DECIMAL_LITERAL=29, BY=30, AND=31, 
		ASC=32, ASSIGN=33, COMMA=34, DESC=35, DOT=36, FALSE=37, FIRST=38, LAST=39, 
		LP=40, IN=41, LIKE=42, NOT=43, NULL=44, NULLS=45, OR=46, PARAM=47, RLIKE=48, 
		RP=49, TRUE=50, INFO=51, FUNCTIONS=52, EQ=53, NEQ=54, LT=55, LTE=56, GT=57, 
		GTE=58, PLUS=59, MINUS=60, ASTERISK=61, SLASH=62, PERCENT=63, OPENING_BRACKET=64, 
		CLOSING_BRACKET=65, UNQUOTED_IDENTIFIER=66, QUOTED_IDENTIFIER=67, EXPR_LINE_COMMENT=68, 
		EXPR_MULTILINE_COMMENT=69, EXPR_WS=70, AS=71, METADATA=72, ON=73, WITH=74, 
		SRC_UNQUOTED_IDENTIFIER=75, SRC_QUOTED_IDENTIFIER=76, SRC_LINE_COMMENT=77, 
		SRC_MULTILINE_COMMENT=78, SRC_WS=79, EXPLAIN_PIPE=80;
	public static final int
		RULE_singleStatement = 0, RULE_query = 1, RULE_sourceCommand = 2, RULE_processingCommand = 3, 
		RULE_whereCommand = 4, RULE_booleanExpression = 5, RULE_regexBooleanExpression = 6, 
		RULE_valueExpression = 7, RULE_operatorExpression = 8, RULE_primaryExpression = 9, 
		RULE_rowCommand = 10, RULE_fields = 11, RULE_field = 12, RULE_fromCommand = 13, 
		RULE_metadata = 14, RULE_evalCommand = 15, RULE_statsCommand = 16, RULE_inlinestatsCommand = 17, 
		RULE_grouping = 18, RULE_sourceIdentifier = 19, RULE_qualifiedName = 20, 
		RULE_identifier = 21, RULE_constant = 22, RULE_limitCommand = 23, RULE_sortCommand = 24, 
		RULE_orderExpression = 25, RULE_keepCommand = 26, RULE_dropCommand = 27, 
		RULE_renameCommand = 28, RULE_renameClause = 29, RULE_dissectCommand = 30, 
		RULE_grokCommand = 31, RULE_mvExpandCommand = 32, RULE_commandOptions = 33, 
		RULE_commandOption = 34, RULE_booleanValue = 35, RULE_numericValue = 36, 
		RULE_decimalValue = 37, RULE_integerValue = 38, RULE_string = 39, RULE_comparisonOperator = 40, 
		RULE_explainCommand = 41, RULE_subqueryExpression = 42, RULE_showCommand = 43, 
		RULE_enrichCommand = 44, RULE_enrichWithClause = 45;
	private static String[] makeRuleNames() {
		return new String[] {
			"singleStatement", "query", "sourceCommand", "processingCommand", "whereCommand", 
			"booleanExpression", "regexBooleanExpression", "valueExpression", "operatorExpression", 
			"primaryExpression", "rowCommand", "fields", "field", "fromCommand", 
			"metadata", "evalCommand", "statsCommand", "inlinestatsCommand", "grouping", 
			"sourceIdentifier", "qualifiedName", "identifier", "constant", "limitCommand", 
			"sortCommand", "orderExpression", "keepCommand", "dropCommand", "renameCommand", 
			"renameClause", "dissectCommand", "grokCommand", "mvExpandCommand", "commandOptions", 
			"commandOption", "booleanValue", "numericValue", "decimalValue", "integerValue", 
			"string", "comparisonOperator", "explainCommand", "subqueryExpression", 
			"showCommand", "enrichCommand", "enrichWithClause"
		};
	}
	public static final String[] ruleNames = makeRuleNames();

	private static String[] makeLiteralNames() {
		return new String[] {
			null, "'dissect'", "'drop'", "'enrich'", "'eval'", "'explain'", "'from'", 
			"'grok'", "'inlinestats'", "'keep'", "'limit'", "'mv_expand'", "'project'", 
			"'rename'", "'row'", "'show'", "'sort'", "'stats'", "'where'", null, 
			null, null, null, null, null, null, null, null, null, null, "'by'", "'and'", 
			"'asc'", null, null, "'desc'", "'.'", "'false'", "'first'", "'last'", 
			"'('", "'in'", "'like'", "'not'", "'null'", "'nulls'", "'or'", "'?'", 
			"'rlike'", "')'", "'true'", "'info'", "'functions'", "'=='", "'!='", 
			"'<'", "'<='", "'>'", "'>='", "'+'", "'-'", "'*'", "'/'", "'%'", null, 
			"']'", null, null, null, null, null, "'as'", "'metadata'", "'on'", "'with'"
		};
	}
	private static final String[] _LITERAL_NAMES = makeLiteralNames();
	private static String[] makeSymbolicNames() {
		return new String[] {
			null, "DISSECT", "DROP", "ENRICH", "EVAL", "EXPLAIN", "FROM", "GROK", 
			"INLINESTATS", "KEEP", "LIMIT", "MV_EXPAND", "PROJECT", "RENAME", "ROW", 
			"SHOW", "SORT", "STATS", "WHERE", "UNKNOWN_CMD", "LINE_COMMENT", "MULTILINE_COMMENT", 
			"WS", "EXPLAIN_WS", "EXPLAIN_LINE_COMMENT", "EXPLAIN_MULTILINE_COMMENT", 
			"PIPE", "STRING", "INTEGER_LITERAL", "DECIMAL_LITERAL", "BY", "AND", 
			"ASC", "ASSIGN", "COMMA", "DESC", "DOT", "FALSE", "FIRST", "LAST", "LP", 
			"IN", "LIKE", "NOT", "NULL", "NULLS", "OR", "PARAM", "RLIKE", "RP", "TRUE", 
			"INFO", "FUNCTIONS", "EQ", "NEQ", "LT", "LTE", "GT", "GTE", "PLUS", "MINUS", 
			"ASTERISK", "SLASH", "PERCENT", "OPENING_BRACKET", "CLOSING_BRACKET", 
			"UNQUOTED_IDENTIFIER", "QUOTED_IDENTIFIER", "EXPR_LINE_COMMENT", "EXPR_MULTILINE_COMMENT", 
			"EXPR_WS", "AS", "METADATA", "ON", "WITH", "SRC_UNQUOTED_IDENTIFIER", 
			"SRC_QUOTED_IDENTIFIER", "SRC_LINE_COMMENT", "SRC_MULTILINE_COMMENT", 
			"SRC_WS", "EXPLAIN_PIPE"
		};
	}
	private static final String[] _SYMBOLIC_NAMES = makeSymbolicNames();
	public static final Vocabulary VOCABULARY = new VocabularyImpl(_LITERAL_NAMES, _SYMBOLIC_NAMES);

	/**
	 * @deprecated Use {@link #VOCABULARY} instead.
	 */
	@Deprecated
	public static final String[] tokenNames;
	static {
		tokenNames = new String[_SYMBOLIC_NAMES.length];
		for (int i = 0; i < tokenNames.length; i++) {
			tokenNames[i] = VOCABULARY.getLiteralName(i);
			if (tokenNames[i] == null) {
				tokenNames[i] = VOCABULARY.getSymbolicName(i);
			}

			if (tokenNames[i] == null) {
				tokenNames[i] = "<INVALID>";
			}
		}
	}

	@Override
	@Deprecated
	public String[] getTokenNames() {
		return tokenNames;
	}

	@Override

	public Vocabulary getVocabulary() {
		return VOCABULARY;
	}

	@Override
	public String getGrammarFileName() { return "EsqlBaseParser.g4"; }

	@Override
	public String[] getRuleNames() { return ruleNames; }

	@Override
	public String getSerializedATN() { return _serializedATN; }

	@Override
	public ATN getATN() { return _ATN; }

	public EsqlBaseParser(TokenStream input) {
		super(input);
		_interp = new ParserATNSimulator(this,_ATN,_decisionToDFA,_sharedContextCache);
	}

	public static class SingleStatementContext extends ParserRuleContext {
		public QueryContext query() {
			return getRuleContext(QueryContext.class,0);
		}
		public TerminalNode EOF() { return getToken(EsqlBaseParser.EOF, 0); }
		public SingleStatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_singleStatement; }
	}

	public final SingleStatementContext singleStatement() throws RecognitionException {
		SingleStatementContext _localctx = new SingleStatementContext(_ctx, getState());
		enterRule(_localctx, 0, RULE_singleStatement);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(92);
			query(0);
			setState(93);
			match(EOF);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class QueryContext extends ParserRuleContext {
		public QueryContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_query; }
	 
		public QueryContext() { }
		public void copyFrom(QueryContext ctx) {
			super.copyFrom(ctx);
		}
	}
	public static class CompositeQueryContext extends QueryContext {
		public QueryContext query() {
			return getRuleContext(QueryContext.class,0);
		}
		public TerminalNode PIPE() { return getToken(EsqlBaseParser.PIPE, 0); }
		public ProcessingCommandContext processingCommand() {
			return getRuleContext(ProcessingCommandContext.class,0);
		}
		public CompositeQueryContext(QueryContext ctx) { copyFrom(ctx); }
	}
	public static class SingleCommandQueryContext extends QueryContext {
		public SourceCommandContext sourceCommand() {
			return getRuleContext(SourceCommandContext.class,0);
		}
		public SingleCommandQueryContext(QueryContext ctx) { copyFrom(ctx); }
	}

	public final QueryContext query() throws RecognitionException {
		return query(0);
	}

	private QueryContext query(int _p) throws RecognitionException {
		ParserRuleContext _parentctx = _ctx;
		int _parentState = getState();
		QueryContext _localctx = new QueryContext(_ctx, _parentState);
		QueryContext _prevctx = _localctx;
		int _startState = 2;
		enterRecursionRule(_localctx, 2, RULE_query, _p);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			{
			_localctx = new SingleCommandQueryContext(_localctx);
			_ctx = _localctx;
			_prevctx = _localctx;

			setState(96);
			sourceCommand();
			}
			_ctx.stop = _input.LT(-1);
			setState(103);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,0,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					if ( _parseListeners!=null ) triggerExitRuleEvent();
					_prevctx = _localctx;
					{
					{
					_localctx = new CompositeQueryContext(new QueryContext(_parentctx, _parentState));
					pushNewRecursionContext(_localctx, _startState, RULE_query);
					setState(98);
					if (!(precpred(_ctx, 1))) throw new FailedPredicateException(this, "precpred(_ctx, 1)");
					setState(99);
					match(PIPE);
					setState(100);
					processingCommand();
					}
					} 
				}
				setState(105);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,0,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			unrollRecursionContexts(_parentctx);
		}
		return _localctx;
	}

	public static class SourceCommandContext extends ParserRuleContext {
		public ExplainCommandContext explainCommand() {
			return getRuleContext(ExplainCommandContext.class,0);
		}
		public FromCommandContext fromCommand() {
			return getRuleContext(FromCommandContext.class,0);
		}
		public RowCommandContext rowCommand() {
			return getRuleContext(RowCommandContext.class,0);
		}
		public ShowCommandContext showCommand() {
			return getRuleContext(ShowCommandContext.class,0);
		}
		public SourceCommandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_sourceCommand; }
	}

	public final SourceCommandContext sourceCommand() throws RecognitionException {
		SourceCommandContext _localctx = new SourceCommandContext(_ctx, getState());
		enterRule(_localctx, 4, RULE_sourceCommand);
		try {
			setState(110);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case EXPLAIN:
				enterOuterAlt(_localctx, 1);
				{
				setState(106);
				explainCommand();
				}
				break;
			case FROM:
				enterOuterAlt(_localctx, 2);
				{
				setState(107);
				fromCommand();
				}
				break;
			case ROW:
				enterOuterAlt(_localctx, 3);
				{
				setState(108);
				rowCommand();
				}
				break;
			case SHOW:
				enterOuterAlt(_localctx, 4);
				{
				setState(109);
				showCommand();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ProcessingCommandContext extends ParserRuleContext {
		public EvalCommandContext evalCommand() {
			return getRuleContext(EvalCommandContext.class,0);
		}
		public InlinestatsCommandContext inlinestatsCommand() {
			return getRuleContext(InlinestatsCommandContext.class,0);
		}
		public LimitCommandContext limitCommand() {
			return getRuleContext(LimitCommandContext.class,0);
		}
		public KeepCommandContext keepCommand() {
			return getRuleContext(KeepCommandContext.class,0);
		}
		public SortCommandContext sortCommand() {
			return getRuleContext(SortCommandContext.class,0);
		}
		public StatsCommandContext statsCommand() {
			return getRuleContext(StatsCommandContext.class,0);
		}
		public WhereCommandContext whereCommand() {
			return getRuleContext(WhereCommandContext.class,0);
		}
		public DropCommandContext dropCommand() {
			return getRuleContext(DropCommandContext.class,0);
		}
		public RenameCommandContext renameCommand() {
			return getRuleContext(RenameCommandContext.class,0);
		}
		public DissectCommandContext dissectCommand() {
			return getRuleContext(DissectCommandContext.class,0);
		}
		public GrokCommandContext grokCommand() {
			return getRuleContext(GrokCommandContext.class,0);
		}
		public EnrichCommandContext enrichCommand() {
			return getRuleContext(EnrichCommandContext.class,0);
		}
		public MvExpandCommandContext mvExpandCommand() {
			return getRuleContext(MvExpandCommandContext.class,0);
		}
		public ProcessingCommandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_processingCommand; }
	}

	public final ProcessingCommandContext processingCommand() throws RecognitionException {
		ProcessingCommandContext _localctx = new ProcessingCommandContext(_ctx, getState());
		enterRule(_localctx, 6, RULE_processingCommand);
		try {
			setState(125);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case EVAL:
				enterOuterAlt(_localctx, 1);
				{
				setState(112);
				evalCommand();
				}
				break;
			case INLINESTATS:
				enterOuterAlt(_localctx, 2);
				{
				setState(113);
				inlinestatsCommand();
				}
				break;
			case LIMIT:
				enterOuterAlt(_localctx, 3);
				{
				setState(114);
				limitCommand();
				}
				break;
			case KEEP:
			case PROJECT:
				enterOuterAlt(_localctx, 4);
				{
				setState(115);
				keepCommand();
				}
				break;
			case SORT:
				enterOuterAlt(_localctx, 5);
				{
				setState(116);
				sortCommand();
				}
				break;
			case STATS:
				enterOuterAlt(_localctx, 6);
				{
				setState(117);
				statsCommand();
				}
				break;
			case WHERE:
				enterOuterAlt(_localctx, 7);
				{
				setState(118);
				whereCommand();
				}
				break;
			case DROP:
				enterOuterAlt(_localctx, 8);
				{
				setState(119);
				dropCommand();
				}
				break;
			case RENAME:
				enterOuterAlt(_localctx, 9);
				{
				setState(120);
				renameCommand();
				}
				break;
			case DISSECT:
				enterOuterAlt(_localctx, 10);
				{
				setState(121);
				dissectCommand();
				}
				break;
			case GROK:
				enterOuterAlt(_localctx, 11);
				{
				setState(122);
				grokCommand();
				}
				break;
			case ENRICH:
				enterOuterAlt(_localctx, 12);
				{
				setState(123);
				enrichCommand();
				}
				break;
			case MV_EXPAND:
				enterOuterAlt(_localctx, 13);
				{
				setState(124);
				mvExpandCommand();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class WhereCommandContext extends ParserRuleContext {
		public TerminalNode WHERE() { return getToken(EsqlBaseParser.WHERE, 0); }
		public BooleanExpressionContext booleanExpression() {
			return getRuleContext(BooleanExpressionContext.class,0);
		}
		public WhereCommandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_whereCommand; }
	}

	public final WhereCommandContext whereCommand() throws RecognitionException {
		WhereCommandContext _localctx = new WhereCommandContext(_ctx, getState());
		enterRule(_localctx, 8, RULE_whereCommand);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(127);
			match(WHERE);
			setState(128);
			booleanExpression(0);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class BooleanExpressionContext extends ParserRuleContext {
		public BooleanExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_booleanExpression; }
	 
		public BooleanExpressionContext() { }
		public void copyFrom(BooleanExpressionContext ctx) {
			super.copyFrom(ctx);
		}
	}
	public static class LogicalNotContext extends BooleanExpressionContext {
		public TerminalNode NOT() { return getToken(EsqlBaseParser.NOT, 0); }
		public BooleanExpressionContext booleanExpression() {
			return getRuleContext(BooleanExpressionContext.class,0);
		}
		public LogicalNotContext(BooleanExpressionContext ctx) { copyFrom(ctx); }
	}
	public static class BooleanDefaultContext extends BooleanExpressionContext {
		public ValueExpressionContext valueExpression() {
			return getRuleContext(ValueExpressionContext.class,0);
		}
		public BooleanDefaultContext(BooleanExpressionContext ctx) { copyFrom(ctx); }
	}
	public static class RegexExpressionContext extends BooleanExpressionContext {
		public RegexBooleanExpressionContext regexBooleanExpression() {
			return getRuleContext(RegexBooleanExpressionContext.class,0);
		}
		public RegexExpressionContext(BooleanExpressionContext ctx) { copyFrom(ctx); }
	}
	public static class LogicalInContext extends BooleanExpressionContext {
		public List<ValueExpressionContext> valueExpression() {
			return getRuleContexts(ValueExpressionContext.class);
		}
		public ValueExpressionContext valueExpression(int i) {
			return getRuleContext(ValueExpressionContext.class,i);
		}
		public TerminalNode IN() { return getToken(EsqlBaseParser.IN, 0); }
		public TerminalNode LP() { return getToken(EsqlBaseParser.LP, 0); }
		public TerminalNode RP() { return getToken(EsqlBaseParser.RP, 0); }
		public TerminalNode NOT() { return getToken(EsqlBaseParser.NOT, 0); }
		public List<TerminalNode> COMMA() { return getTokens(EsqlBaseParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(EsqlBaseParser.COMMA, i);
		}
		public LogicalInContext(BooleanExpressionContext ctx) { copyFrom(ctx); }
	}
	public static class LogicalBinaryContext extends BooleanExpressionContext {
		public BooleanExpressionContext left;
		public Token operator;
		public BooleanExpressionContext right;
		public List<BooleanExpressionContext> booleanExpression() {
			return getRuleContexts(BooleanExpressionContext.class);
		}
		public BooleanExpressionContext booleanExpression(int i) {
			return getRuleContext(BooleanExpressionContext.class,i);
		}
		public TerminalNode AND() { return getToken(EsqlBaseParser.AND, 0); }
		public TerminalNode OR() { return getToken(EsqlBaseParser.OR, 0); }
		public LogicalBinaryContext(BooleanExpressionContext ctx) { copyFrom(ctx); }
	}

	public final BooleanExpressionContext booleanExpression() throws RecognitionException {
		return booleanExpression(0);
	}

	private BooleanExpressionContext booleanExpression(int _p) throws RecognitionException {
		ParserRuleContext _parentctx = _ctx;
		int _parentState = getState();
		BooleanExpressionContext _localctx = new BooleanExpressionContext(_ctx, _parentState);
		BooleanExpressionContext _prevctx = _localctx;
		int _startState = 10;
		enterRecursionRule(_localctx, 10, RULE_booleanExpression, _p);
		int _la;
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(151);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,5,_ctx) ) {
			case 1:
				{
				_localctx = new LogicalNotContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;

				setState(131);
				match(NOT);
				setState(132);
				booleanExpression(6);
				}
				break;
			case 2:
				{
				_localctx = new BooleanDefaultContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(133);
				valueExpression();
				}
				break;
			case 3:
				{
				_localctx = new RegexExpressionContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(134);
				regexBooleanExpression();
				}
				break;
			case 4:
				{
				_localctx = new LogicalInContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(135);
				valueExpression();
				setState(137);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==NOT) {
					{
					setState(136);
					match(NOT);
					}
				}

				setState(139);
				match(IN);
				setState(140);
				match(LP);
				setState(141);
				valueExpression();
				setState(146);
				_errHandler.sync(this);
				_la = _input.LA(1);
				while (_la==COMMA) {
					{
					{
					setState(142);
					match(COMMA);
					setState(143);
					valueExpression();
					}
					}
					setState(148);
					_errHandler.sync(this);
					_la = _input.LA(1);
				}
				setState(149);
				match(RP);
				}
				break;
			}
			_ctx.stop = _input.LT(-1);
			setState(161);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,7,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					if ( _parseListeners!=null ) triggerExitRuleEvent();
					_prevctx = _localctx;
					{
					setState(159);
					_errHandler.sync(this);
					switch ( getInterpreter().adaptivePredict(_input,6,_ctx) ) {
					case 1:
						{
						_localctx = new LogicalBinaryContext(new BooleanExpressionContext(_parentctx, _parentState));
						((LogicalBinaryContext)_localctx).left = _prevctx;
						pushNewRecursionContext(_localctx, _startState, RULE_booleanExpression);
						setState(153);
						if (!(precpred(_ctx, 3))) throw new FailedPredicateException(this, "precpred(_ctx, 3)");
						setState(154);
						((LogicalBinaryContext)_localctx).operator = match(AND);
						setState(155);
						((LogicalBinaryContext)_localctx).right = booleanExpression(4);
						}
						break;
					case 2:
						{
						_localctx = new LogicalBinaryContext(new BooleanExpressionContext(_parentctx, _parentState));
						((LogicalBinaryContext)_localctx).left = _prevctx;
						pushNewRecursionContext(_localctx, _startState, RULE_booleanExpression);
						setState(156);
						if (!(precpred(_ctx, 2))) throw new FailedPredicateException(this, "precpred(_ctx, 2)");
						setState(157);
						((LogicalBinaryContext)_localctx).operator = match(OR);
						setState(158);
						((LogicalBinaryContext)_localctx).right = booleanExpression(3);
						}
						break;
					}
					} 
				}
				setState(163);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,7,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			unrollRecursionContexts(_parentctx);
		}
		return _localctx;
	}

	public static class RegexBooleanExpressionContext extends ParserRuleContext {
		public Token kind;
		public StringContext pattern;
		public ValueExpressionContext valueExpression() {
			return getRuleContext(ValueExpressionContext.class,0);
		}
		public TerminalNode LIKE() { return getToken(EsqlBaseParser.LIKE, 0); }
		public StringContext string() {
			return getRuleContext(StringContext.class,0);
		}
		public TerminalNode NOT() { return getToken(EsqlBaseParser.NOT, 0); }
		public TerminalNode RLIKE() { return getToken(EsqlBaseParser.RLIKE, 0); }
		public RegexBooleanExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_regexBooleanExpression; }
	}

	public final RegexBooleanExpressionContext regexBooleanExpression() throws RecognitionException {
		RegexBooleanExpressionContext _localctx = new RegexBooleanExpressionContext(_ctx, getState());
		enterRule(_localctx, 12, RULE_regexBooleanExpression);
		int _la;
		try {
			setState(178);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,10,_ctx) ) {
			case 1:
				enterOuterAlt(_localctx, 1);
				{
				setState(164);
				valueExpression();
				setState(166);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==NOT) {
					{
					setState(165);
					match(NOT);
					}
				}

				setState(168);
				((RegexBooleanExpressionContext)_localctx).kind = match(LIKE);
				setState(169);
				((RegexBooleanExpressionContext)_localctx).pattern = string();
				}
				break;
			case 2:
				enterOuterAlt(_localctx, 2);
				{
				setState(171);
				valueExpression();
				setState(173);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==NOT) {
					{
					setState(172);
					match(NOT);
					}
				}

				setState(175);
				((RegexBooleanExpressionContext)_localctx).kind = match(RLIKE);
				setState(176);
				((RegexBooleanExpressionContext)_localctx).pattern = string();
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ValueExpressionContext extends ParserRuleContext {
		public ValueExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_valueExpression; }
	 
		public ValueExpressionContext() { }
		public void copyFrom(ValueExpressionContext ctx) {
			super.copyFrom(ctx);
		}
	}
	public static class ValueExpressionDefaultContext extends ValueExpressionContext {
		public OperatorExpressionContext operatorExpression() {
			return getRuleContext(OperatorExpressionContext.class,0);
		}
		public ValueExpressionDefaultContext(ValueExpressionContext ctx) { copyFrom(ctx); }
	}
	public static class ComparisonContext extends ValueExpressionContext {
		public OperatorExpressionContext left;
		public OperatorExpressionContext right;
		public ComparisonOperatorContext comparisonOperator() {
			return getRuleContext(ComparisonOperatorContext.class,0);
		}
		public List<OperatorExpressionContext> operatorExpression() {
			return getRuleContexts(OperatorExpressionContext.class);
		}
		public OperatorExpressionContext operatorExpression(int i) {
			return getRuleContext(OperatorExpressionContext.class,i);
		}
		public ComparisonContext(ValueExpressionContext ctx) { copyFrom(ctx); }
	}

	public final ValueExpressionContext valueExpression() throws RecognitionException {
		ValueExpressionContext _localctx = new ValueExpressionContext(_ctx, getState());
		enterRule(_localctx, 14, RULE_valueExpression);
		try {
			setState(185);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,11,_ctx) ) {
			case 1:
				_localctx = new ValueExpressionDefaultContext(_localctx);
				enterOuterAlt(_localctx, 1);
				{
				setState(180);
				operatorExpression(0);
				}
				break;
			case 2:
				_localctx = new ComparisonContext(_localctx);
				enterOuterAlt(_localctx, 2);
				{
				setState(181);
				((ComparisonContext)_localctx).left = operatorExpression(0);
				setState(182);
				comparisonOperator();
				setState(183);
				((ComparisonContext)_localctx).right = operatorExpression(0);
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class OperatorExpressionContext extends ParserRuleContext {
		public OperatorExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_operatorExpression; }
	 
		public OperatorExpressionContext() { }
		public void copyFrom(OperatorExpressionContext ctx) {
			super.copyFrom(ctx);
		}
	}
	public static class OperatorExpressionDefaultContext extends OperatorExpressionContext {
		public PrimaryExpressionContext primaryExpression() {
			return getRuleContext(PrimaryExpressionContext.class,0);
		}
		public OperatorExpressionDefaultContext(OperatorExpressionContext ctx) { copyFrom(ctx); }
	}
	public static class ArithmeticBinaryContext extends OperatorExpressionContext {
		public OperatorExpressionContext left;
		public Token operator;
		public OperatorExpressionContext right;
		public List<OperatorExpressionContext> operatorExpression() {
			return getRuleContexts(OperatorExpressionContext.class);
		}
		public OperatorExpressionContext operatorExpression(int i) {
			return getRuleContext(OperatorExpressionContext.class,i);
		}
		public TerminalNode ASTERISK() { return getToken(EsqlBaseParser.ASTERISK, 0); }
		public TerminalNode SLASH() { return getToken(EsqlBaseParser.SLASH, 0); }
		public TerminalNode PERCENT() { return getToken(EsqlBaseParser.PERCENT, 0); }
		public TerminalNode PLUS() { return getToken(EsqlBaseParser.PLUS, 0); }
		public TerminalNode MINUS() { return getToken(EsqlBaseParser.MINUS, 0); }
		public ArithmeticBinaryContext(OperatorExpressionContext ctx) { copyFrom(ctx); }
	}
	public static class ArithmeticUnaryContext extends OperatorExpressionContext {
		public Token operator;
		public OperatorExpressionContext operatorExpression() {
			return getRuleContext(OperatorExpressionContext.class,0);
		}
		public TerminalNode MINUS() { return getToken(EsqlBaseParser.MINUS, 0); }
		public TerminalNode PLUS() { return getToken(EsqlBaseParser.PLUS, 0); }
		public ArithmeticUnaryContext(OperatorExpressionContext ctx) { copyFrom(ctx); }
	}

	public final OperatorExpressionContext operatorExpression() throws RecognitionException {
		return operatorExpression(0);
	}

	private OperatorExpressionContext operatorExpression(int _p) throws RecognitionException {
		ParserRuleContext _parentctx = _ctx;
		int _parentState = getState();
		OperatorExpressionContext _localctx = new OperatorExpressionContext(_ctx, _parentState);
		OperatorExpressionContext _prevctx = _localctx;
		int _startState = 16;
		enterRecursionRule(_localctx, 16, RULE_operatorExpression, _p);
		int _la;
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(191);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case STRING:
			case INTEGER_LITERAL:
			case DECIMAL_LITERAL:
			case FALSE:
			case LP:
			case NULL:
			case PARAM:
			case TRUE:
			case OPENING_BRACKET:
			case UNQUOTED_IDENTIFIER:
			case QUOTED_IDENTIFIER:
				{
				_localctx = new OperatorExpressionDefaultContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;

				setState(188);
				primaryExpression();
				}
				break;
			case PLUS:
			case MINUS:
				{
				_localctx = new ArithmeticUnaryContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(189);
				((ArithmeticUnaryContext)_localctx).operator = _input.LT(1);
				_la = _input.LA(1);
				if ( !(_la==PLUS || _la==MINUS) ) {
					((ArithmeticUnaryContext)_localctx).operator = (Token)_errHandler.recoverInline(this);
				}
				else {
					if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
					_errHandler.reportMatch(this);
					consume();
				}
				setState(190);
				operatorExpression(3);
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
			_ctx.stop = _input.LT(-1);
			setState(201);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,14,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					if ( _parseListeners!=null ) triggerExitRuleEvent();
					_prevctx = _localctx;
					{
					setState(199);
					_errHandler.sync(this);
					switch ( getInterpreter().adaptivePredict(_input,13,_ctx) ) {
					case 1:
						{
						_localctx = new ArithmeticBinaryContext(new OperatorExpressionContext(_parentctx, _parentState));
						((ArithmeticBinaryContext)_localctx).left = _prevctx;
						pushNewRecursionContext(_localctx, _startState, RULE_operatorExpression);
						setState(193);
						if (!(precpred(_ctx, 2))) throw new FailedPredicateException(this, "precpred(_ctx, 2)");
						setState(194);
						((ArithmeticBinaryContext)_localctx).operator = _input.LT(1);
						_la = _input.LA(1);
						if ( !((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << ASTERISK) | (1L << SLASH) | (1L << PERCENT))) != 0)) ) {
							((ArithmeticBinaryContext)_localctx).operator = (Token)_errHandler.recoverInline(this);
						}
						else {
							if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
							_errHandler.reportMatch(this);
							consume();
						}
						setState(195);
						((ArithmeticBinaryContext)_localctx).right = operatorExpression(3);
						}
						break;
					case 2:
						{
						_localctx = new ArithmeticBinaryContext(new OperatorExpressionContext(_parentctx, _parentState));
						((ArithmeticBinaryContext)_localctx).left = _prevctx;
						pushNewRecursionContext(_localctx, _startState, RULE_operatorExpression);
						setState(196);
						if (!(precpred(_ctx, 1))) throw new FailedPredicateException(this, "precpred(_ctx, 1)");
						setState(197);
						((ArithmeticBinaryContext)_localctx).operator = _input.LT(1);
						_la = _input.LA(1);
						if ( !(_la==PLUS || _la==MINUS) ) {
							((ArithmeticBinaryContext)_localctx).operator = (Token)_errHandler.recoverInline(this);
						}
						else {
							if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
							_errHandler.reportMatch(this);
							consume();
						}
						setState(198);
						((ArithmeticBinaryContext)_localctx).right = operatorExpression(2);
						}
						break;
					}
					} 
				}
				setState(203);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,14,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			unrollRecursionContexts(_parentctx);
		}
		return _localctx;
	}

	public static class PrimaryExpressionContext extends ParserRuleContext {
		public PrimaryExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_primaryExpression; }
	 
		public PrimaryExpressionContext() { }
		public void copyFrom(PrimaryExpressionContext ctx) {
			super.copyFrom(ctx);
		}
	}
	public static class DereferenceContext extends PrimaryExpressionContext {
		public QualifiedNameContext qualifiedName() {
			return getRuleContext(QualifiedNameContext.class,0);
		}
		public DereferenceContext(PrimaryExpressionContext ctx) { copyFrom(ctx); }
	}
	public static class ConstantDefaultContext extends PrimaryExpressionContext {
		public ConstantContext constant() {
			return getRuleContext(ConstantContext.class,0);
		}
		public ConstantDefaultContext(PrimaryExpressionContext ctx) { copyFrom(ctx); }
	}
	public static class ParenthesizedExpressionContext extends PrimaryExpressionContext {
		public TerminalNode LP() { return getToken(EsqlBaseParser.LP, 0); }
		public BooleanExpressionContext booleanExpression() {
			return getRuleContext(BooleanExpressionContext.class,0);
		}
		public TerminalNode RP() { return getToken(EsqlBaseParser.RP, 0); }
		public ParenthesizedExpressionContext(PrimaryExpressionContext ctx) { copyFrom(ctx); }
	}
	public static class FunctionExpressionContext extends PrimaryExpressionContext {
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public TerminalNode LP() { return getToken(EsqlBaseParser.LP, 0); }
		public TerminalNode RP() { return getToken(EsqlBaseParser.RP, 0); }
		public List<BooleanExpressionContext> booleanExpression() {
			return getRuleContexts(BooleanExpressionContext.class);
		}
		public BooleanExpressionContext booleanExpression(int i) {
			return getRuleContext(BooleanExpressionContext.class,i);
		}
		public List<TerminalNode> COMMA() { return getTokens(EsqlBaseParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(EsqlBaseParser.COMMA, i);
		}
		public FunctionExpressionContext(PrimaryExpressionContext ctx) { copyFrom(ctx); }
	}

	public final PrimaryExpressionContext primaryExpression() throws RecognitionException {
		PrimaryExpressionContext _localctx = new PrimaryExpressionContext(_ctx, getState());
		enterRule(_localctx, 18, RULE_primaryExpression);
		int _la;
		try {
			setState(224);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,17,_ctx) ) {
			case 1:
				_localctx = new ConstantDefaultContext(_localctx);
				enterOuterAlt(_localctx, 1);
				{
				setState(204);
				constant();
				}
				break;
			case 2:
				_localctx = new DereferenceContext(_localctx);
				enterOuterAlt(_localctx, 2);
				{
				setState(205);
				qualifiedName();
				}
				break;
			case 3:
				_localctx = new ParenthesizedExpressionContext(_localctx);
				enterOuterAlt(_localctx, 3);
				{
				setState(206);
				match(LP);
				setState(207);
				booleanExpression(0);
				setState(208);
				match(RP);
				}
				break;
			case 4:
				_localctx = new FunctionExpressionContext(_localctx);
				enterOuterAlt(_localctx, 4);
				{
				setState(210);
				identifier();
				setState(211);
				match(LP);
				setState(220);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (((((_la - 27)) & ~0x3f) == 0 && ((1L << (_la - 27)) & ((1L << (STRING - 27)) | (1L << (INTEGER_LITERAL - 27)) | (1L << (DECIMAL_LITERAL - 27)) | (1L << (FALSE - 27)) | (1L << (LP - 27)) | (1L << (NOT - 27)) | (1L << (NULL - 27)) | (1L << (PARAM - 27)) | (1L << (TRUE - 27)) | (1L << (PLUS - 27)) | (1L << (MINUS - 27)) | (1L << (OPENING_BRACKET - 27)) | (1L << (UNQUOTED_IDENTIFIER - 27)) | (1L << (QUOTED_IDENTIFIER - 27)))) != 0)) {
					{
					setState(212);
					booleanExpression(0);
					setState(217);
					_errHandler.sync(this);
					_la = _input.LA(1);
					while (_la==COMMA) {
						{
						{
						setState(213);
						match(COMMA);
						setState(214);
						booleanExpression(0);
						}
						}
						setState(219);
						_errHandler.sync(this);
						_la = _input.LA(1);
					}
					}
				}

				setState(222);
				match(RP);
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class RowCommandContext extends ParserRuleContext {
		public TerminalNode ROW() { return getToken(EsqlBaseParser.ROW, 0); }
		public FieldsContext fields() {
			return getRuleContext(FieldsContext.class,0);
		}
		public RowCommandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_rowCommand; }
	}

	public final RowCommandContext rowCommand() throws RecognitionException {
		RowCommandContext _localctx = new RowCommandContext(_ctx, getState());
		enterRule(_localctx, 20, RULE_rowCommand);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(226);
			match(ROW);
			setState(227);
			fields();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class FieldsContext extends ParserRuleContext {
		public List<FieldContext> field() {
			return getRuleContexts(FieldContext.class);
		}
		public FieldContext field(int i) {
			return getRuleContext(FieldContext.class,i);
		}
		public List<TerminalNode> COMMA() { return getTokens(EsqlBaseParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(EsqlBaseParser.COMMA, i);
		}
		public FieldsContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_fields; }
	}

	public final FieldsContext fields() throws RecognitionException {
		FieldsContext _localctx = new FieldsContext(_ctx, getState());
		enterRule(_localctx, 22, RULE_fields);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(229);
			field();
			setState(234);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,18,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(230);
					match(COMMA);
					setState(231);
					field();
					}
					} 
				}
				setState(236);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,18,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class FieldContext extends ParserRuleContext {
		public BooleanExpressionContext booleanExpression() {
			return getRuleContext(BooleanExpressionContext.class,0);
		}
		public QualifiedNameContext qualifiedName() {
			return getRuleContext(QualifiedNameContext.class,0);
		}
		public TerminalNode ASSIGN() { return getToken(EsqlBaseParser.ASSIGN, 0); }
		public FieldContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_field; }
	}

	public final FieldContext field() throws RecognitionException {
		FieldContext _localctx = new FieldContext(_ctx, getState());
		enterRule(_localctx, 24, RULE_field);
		try {
			setState(242);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,19,_ctx) ) {
			case 1:
				enterOuterAlt(_localctx, 1);
				{
				setState(237);
				booleanExpression(0);
				}
				break;
			case 2:
				enterOuterAlt(_localctx, 2);
				{
				setState(238);
				qualifiedName();
				setState(239);
				match(ASSIGN);
				setState(240);
				booleanExpression(0);
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class FromCommandContext extends ParserRuleContext {
		public TerminalNode FROM() { return getToken(EsqlBaseParser.FROM, 0); }
		public List<SourceIdentifierContext> sourceIdentifier() {
			return getRuleContexts(SourceIdentifierContext.class);
		}
		public SourceIdentifierContext sourceIdentifier(int i) {
			return getRuleContext(SourceIdentifierContext.class,i);
		}
		public List<TerminalNode> COMMA() { return getTokens(EsqlBaseParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(EsqlBaseParser.COMMA, i);
		}
		public MetadataContext metadata() {
			return getRuleContext(MetadataContext.class,0);
		}
		public FromCommandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_fromCommand; }
	}

	public final FromCommandContext fromCommand() throws RecognitionException {
		FromCommandContext _localctx = new FromCommandContext(_ctx, getState());
		enterRule(_localctx, 26, RULE_fromCommand);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(244);
			match(FROM);
			setState(245);
			sourceIdentifier();
			setState(250);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,20,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(246);
					match(COMMA);
					setState(247);
					sourceIdentifier();
					}
					} 
				}
				setState(252);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,20,_ctx);
			}
			setState(254);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,21,_ctx) ) {
			case 1:
				{
				setState(253);
				metadata();
				}
				break;
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class MetadataContext extends ParserRuleContext {
		public TerminalNode OPENING_BRACKET() { return getToken(EsqlBaseParser.OPENING_BRACKET, 0); }
		public TerminalNode METADATA() { return getToken(EsqlBaseParser.METADATA, 0); }
		public List<SourceIdentifierContext> sourceIdentifier() {
			return getRuleContexts(SourceIdentifierContext.class);
		}
		public SourceIdentifierContext sourceIdentifier(int i) {
			return getRuleContext(SourceIdentifierContext.class,i);
		}
		public TerminalNode CLOSING_BRACKET() { return getToken(EsqlBaseParser.CLOSING_BRACKET, 0); }
		public List<TerminalNode> COMMA() { return getTokens(EsqlBaseParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(EsqlBaseParser.COMMA, i);
		}
		public MetadataContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_metadata; }
	}

	public final MetadataContext metadata() throws RecognitionException {
		MetadataContext _localctx = new MetadataContext(_ctx, getState());
		enterRule(_localctx, 28, RULE_metadata);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(256);
			match(OPENING_BRACKET);
			setState(257);
			match(METADATA);
			setState(258);
			sourceIdentifier();
			setState(263);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==COMMA) {
				{
				{
				setState(259);
				match(COMMA);
				setState(260);
				sourceIdentifier();
				}
				}
				setState(265);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			setState(266);
			match(CLOSING_BRACKET);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class EvalCommandContext extends ParserRuleContext {
		public TerminalNode EVAL() { return getToken(EsqlBaseParser.EVAL, 0); }
		public FieldsContext fields() {
			return getRuleContext(FieldsContext.class,0);
		}
		public EvalCommandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_evalCommand; }
	}

	public final EvalCommandContext evalCommand() throws RecognitionException {
		EvalCommandContext _localctx = new EvalCommandContext(_ctx, getState());
		enterRule(_localctx, 30, RULE_evalCommand);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(268);
			match(EVAL);
			setState(269);
			fields();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class StatsCommandContext extends ParserRuleContext {
		public TerminalNode STATS() { return getToken(EsqlBaseParser.STATS, 0); }
		public FieldsContext fields() {
			return getRuleContext(FieldsContext.class,0);
		}
		public TerminalNode BY() { return getToken(EsqlBaseParser.BY, 0); }
		public GroupingContext grouping() {
			return getRuleContext(GroupingContext.class,0);
		}
		public StatsCommandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_statsCommand; }
	}

	public final StatsCommandContext statsCommand() throws RecognitionException {
		StatsCommandContext _localctx = new StatsCommandContext(_ctx, getState());
		enterRule(_localctx, 32, RULE_statsCommand);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(271);
			match(STATS);
			setState(273);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,23,_ctx) ) {
			case 1:
				{
				setState(272);
				fields();
				}
				break;
			}
			setState(277);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,24,_ctx) ) {
			case 1:
				{
				setState(275);
				match(BY);
				setState(276);
				grouping();
				}
				break;
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class InlinestatsCommandContext extends ParserRuleContext {
		public TerminalNode INLINESTATS() { return getToken(EsqlBaseParser.INLINESTATS, 0); }
		public FieldsContext fields() {
			return getRuleContext(FieldsContext.class,0);
		}
		public TerminalNode BY() { return getToken(EsqlBaseParser.BY, 0); }
		public GroupingContext grouping() {
			return getRuleContext(GroupingContext.class,0);
		}
		public InlinestatsCommandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_inlinestatsCommand; }
	}

	public final InlinestatsCommandContext inlinestatsCommand() throws RecognitionException {
		InlinestatsCommandContext _localctx = new InlinestatsCommandContext(_ctx, getState());
		enterRule(_localctx, 34, RULE_inlinestatsCommand);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(279);
			match(INLINESTATS);
			setState(280);
			fields();
			setState(283);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,25,_ctx) ) {
			case 1:
				{
				setState(281);
				match(BY);
				setState(282);
				grouping();
				}
				break;
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class GroupingContext extends ParserRuleContext {
		public List<QualifiedNameContext> qualifiedName() {
			return getRuleContexts(QualifiedNameContext.class);
		}
		public QualifiedNameContext qualifiedName(int i) {
			return getRuleContext(QualifiedNameContext.class,i);
		}
		public List<TerminalNode> COMMA() { return getTokens(EsqlBaseParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(EsqlBaseParser.COMMA, i);
		}
		public GroupingContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_grouping; }
	}

	public final GroupingContext grouping() throws RecognitionException {
		GroupingContext _localctx = new GroupingContext(_ctx, getState());
		enterRule(_localctx, 36, RULE_grouping);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(285);
			qualifiedName();
			setState(290);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,26,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(286);
					match(COMMA);
					setState(287);
					qualifiedName();
					}
					} 
				}
				setState(292);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,26,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class SourceIdentifierContext extends ParserRuleContext {
		public TerminalNode SRC_UNQUOTED_IDENTIFIER() { return getToken(EsqlBaseParser.SRC_UNQUOTED_IDENTIFIER, 0); }
		public TerminalNode SRC_QUOTED_IDENTIFIER() { return getToken(EsqlBaseParser.SRC_QUOTED_IDENTIFIER, 0); }
		public SourceIdentifierContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_sourceIdentifier; }
	}

	public final SourceIdentifierContext sourceIdentifier() throws RecognitionException {
		SourceIdentifierContext _localctx = new SourceIdentifierContext(_ctx, getState());
		enterRule(_localctx, 38, RULE_sourceIdentifier);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(293);
			_la = _input.LA(1);
			if ( !(_la==SRC_UNQUOTED_IDENTIFIER || _la==SRC_QUOTED_IDENTIFIER) ) {
			_errHandler.recoverInline(this);
			}
			else {
				if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
				_errHandler.reportMatch(this);
				consume();
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class QualifiedNameContext extends ParserRuleContext {
		public List<IdentifierContext> identifier() {
			return getRuleContexts(IdentifierContext.class);
		}
		public IdentifierContext identifier(int i) {
			return getRuleContext(IdentifierContext.class,i);
		}
		public List<TerminalNode> DOT() { return getTokens(EsqlBaseParser.DOT); }
		public TerminalNode DOT(int i) {
			return getToken(EsqlBaseParser.DOT, i);
		}
		public QualifiedNameContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_qualifiedName; }
	}

	public final QualifiedNameContext qualifiedName() throws RecognitionException {
		QualifiedNameContext _localctx = new QualifiedNameContext(_ctx, getState());
		enterRule(_localctx, 40, RULE_qualifiedName);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(295);
			identifier();
			setState(300);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,27,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(296);
					match(DOT);
					setState(297);
					identifier();
					}
					} 
				}
				setState(302);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,27,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class IdentifierContext extends ParserRuleContext {
		public TerminalNode UNQUOTED_IDENTIFIER() { return getToken(EsqlBaseParser.UNQUOTED_IDENTIFIER, 0); }
		public TerminalNode QUOTED_IDENTIFIER() { return getToken(EsqlBaseParser.QUOTED_IDENTIFIER, 0); }
		public IdentifierContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_identifier; }
	}

	public final IdentifierContext identifier() throws RecognitionException {
		IdentifierContext _localctx = new IdentifierContext(_ctx, getState());
		enterRule(_localctx, 42, RULE_identifier);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(303);
			_la = _input.LA(1);
			if ( !(_la==UNQUOTED_IDENTIFIER || _la==QUOTED_IDENTIFIER) ) {
			_errHandler.recoverInline(this);
			}
			else {
				if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
				_errHandler.reportMatch(this);
				consume();
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ConstantContext extends ParserRuleContext {
		public ConstantContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_constant; }
	 
		public ConstantContext() { }
		public void copyFrom(ConstantContext ctx) {
			super.copyFrom(ctx);
		}
	}
	public static class BooleanArrayLiteralContext extends ConstantContext {
		public TerminalNode OPENING_BRACKET() { return getToken(EsqlBaseParser.OPENING_BRACKET, 0); }
		public List<BooleanValueContext> booleanValue() {
			return getRuleContexts(BooleanValueContext.class);
		}
		public BooleanValueContext booleanValue(int i) {
			return getRuleContext(BooleanValueContext.class,i);
		}
		public TerminalNode CLOSING_BRACKET() { return getToken(EsqlBaseParser.CLOSING_BRACKET, 0); }
		public List<TerminalNode> COMMA() { return getTokens(EsqlBaseParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(EsqlBaseParser.COMMA, i);
		}
		public BooleanArrayLiteralContext(ConstantContext ctx) { copyFrom(ctx); }
	}
	public static class DecimalLiteralContext extends ConstantContext {
		public DecimalValueContext decimalValue() {
			return getRuleContext(DecimalValueContext.class,0);
		}
		public DecimalLiteralContext(ConstantContext ctx) { copyFrom(ctx); }
	}
	public static class NullLiteralContext extends ConstantContext {
		public TerminalNode NULL() { return getToken(EsqlBaseParser.NULL, 0); }
		public NullLiteralContext(ConstantContext ctx) { copyFrom(ctx); }
	}
	public static class QualifiedIntegerLiteralContext extends ConstantContext {
		public IntegerValueContext integerValue() {
			return getRuleContext(IntegerValueContext.class,0);
		}
		public TerminalNode UNQUOTED_IDENTIFIER() { return getToken(EsqlBaseParser.UNQUOTED_IDENTIFIER, 0); }
		public QualifiedIntegerLiteralContext(ConstantContext ctx) { copyFrom(ctx); }
	}
	public static class StringArrayLiteralContext extends ConstantContext {
		public TerminalNode OPENING_BRACKET() { return getToken(EsqlBaseParser.OPENING_BRACKET, 0); }
		public List<StringContext> string() {
			return getRuleContexts(StringContext.class);
		}
		public StringContext string(int i) {
			return getRuleContext(StringContext.class,i);
		}
		public TerminalNode CLOSING_BRACKET() { return getToken(EsqlBaseParser.CLOSING_BRACKET, 0); }
		public List<TerminalNode> COMMA() { return getTokens(EsqlBaseParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(EsqlBaseParser.COMMA, i);
		}
		public StringArrayLiteralContext(ConstantContext ctx) { copyFrom(ctx); }
	}
	public static class StringLiteralContext extends ConstantContext {
		public StringContext string() {
			return getRuleContext(StringContext.class,0);
		}
		public StringLiteralContext(ConstantContext ctx) { copyFrom(ctx); }
	}
	public static class NumericArrayLiteralContext extends ConstantContext {
		public TerminalNode OPENING_BRACKET() { return getToken(EsqlBaseParser.OPENING_BRACKET, 0); }
		public List<NumericValueContext> numericValue() {
			return getRuleContexts(NumericValueContext.class);
		}
		public NumericValueContext numericValue(int i) {
			return getRuleContext(NumericValueContext.class,i);
		}
		public TerminalNode CLOSING_BRACKET() { return getToken(EsqlBaseParser.CLOSING_BRACKET, 0); }
		public List<TerminalNode> COMMA() { return getTokens(EsqlBaseParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(EsqlBaseParser.COMMA, i);
		}
		public NumericArrayLiteralContext(ConstantContext ctx) { copyFrom(ctx); }
	}
	public static class InputParamContext extends ConstantContext {
		public TerminalNode PARAM() { return getToken(EsqlBaseParser.PARAM, 0); }
		public InputParamContext(ConstantContext ctx) { copyFrom(ctx); }
	}
	public static class IntegerLiteralContext extends ConstantContext {
		public IntegerValueContext integerValue() {
			return getRuleContext(IntegerValueContext.class,0);
		}
		public IntegerLiteralContext(ConstantContext ctx) { copyFrom(ctx); }
	}
	public static class BooleanLiteralContext extends ConstantContext {
		public BooleanValueContext booleanValue() {
			return getRuleContext(BooleanValueContext.class,0);
		}
		public BooleanLiteralContext(ConstantContext ctx) { copyFrom(ctx); }
	}

	public final ConstantContext constant() throws RecognitionException {
		ConstantContext _localctx = new ConstantContext(_ctx, getState());
		enterRule(_localctx, 44, RULE_constant);
		int _la;
		try {
			setState(347);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,31,_ctx) ) {
			case 1:
				_localctx = new NullLiteralContext(_localctx);
				enterOuterAlt(_localctx, 1);
				{
				setState(305);
				match(NULL);
				}
				break;
			case 2:
				_localctx = new QualifiedIntegerLiteralContext(_localctx);
				enterOuterAlt(_localctx, 2);
				{
				setState(306);
				integerValue();
				setState(307);
				match(UNQUOTED_IDENTIFIER);
				}
				break;
			case 3:
				_localctx = new DecimalLiteralContext(_localctx);
				enterOuterAlt(_localctx, 3);
				{
				setState(309);
				decimalValue();
				}
				break;
			case 4:
				_localctx = new IntegerLiteralContext(_localctx);
				enterOuterAlt(_localctx, 4);
				{
				setState(310);
				integerValue();
				}
				break;
			case 5:
				_localctx = new BooleanLiteralContext(_localctx);
				enterOuterAlt(_localctx, 5);
				{
				setState(311);
				booleanValue();
				}
				break;
			case 6:
				_localctx = new InputParamContext(_localctx);
				enterOuterAlt(_localctx, 6);
				{
				setState(312);
				match(PARAM);
				}
				break;
			case 7:
				_localctx = new StringLiteralContext(_localctx);
				enterOuterAlt(_localctx, 7);
				{
				setState(313);
				string();
				}
				break;
			case 8:
				_localctx = new NumericArrayLiteralContext(_localctx);
				enterOuterAlt(_localctx, 8);
				{
				setState(314);
				match(OPENING_BRACKET);
				setState(315);
				numericValue();
				setState(320);
				_errHandler.sync(this);
				_la = _input.LA(1);
				while (_la==COMMA) {
					{
					{
					setState(316);
					match(COMMA);
					setState(317);
					numericValue();
					}
					}
					setState(322);
					_errHandler.sync(this);
					_la = _input.LA(1);
				}
				setState(323);
				match(CLOSING_BRACKET);
				}
				break;
			case 9:
				_localctx = new BooleanArrayLiteralContext(_localctx);
				enterOuterAlt(_localctx, 9);
				{
				setState(325);
				match(OPENING_BRACKET);
				setState(326);
				booleanValue();
				setState(331);
				_errHandler.sync(this);
				_la = _input.LA(1);
				while (_la==COMMA) {
					{
					{
					setState(327);
					match(COMMA);
					setState(328);
					booleanValue();
					}
					}
					setState(333);
					_errHandler.sync(this);
					_la = _input.LA(1);
				}
				setState(334);
				match(CLOSING_BRACKET);
				}
				break;
			case 10:
				_localctx = new StringArrayLiteralContext(_localctx);
				enterOuterAlt(_localctx, 10);
				{
				setState(336);
				match(OPENING_BRACKET);
				setState(337);
				string();
				setState(342);
				_errHandler.sync(this);
				_la = _input.LA(1);
				while (_la==COMMA) {
					{
					{
					setState(338);
					match(COMMA);
					setState(339);
					string();
					}
					}
					setState(344);
					_errHandler.sync(this);
					_la = _input.LA(1);
				}
				setState(345);
				match(CLOSING_BRACKET);
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class LimitCommandContext extends ParserRuleContext {
		public TerminalNode LIMIT() { return getToken(EsqlBaseParser.LIMIT, 0); }
		public TerminalNode INTEGER_LITERAL() { return getToken(EsqlBaseParser.INTEGER_LITERAL, 0); }
		public LimitCommandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_limitCommand; }
	}

	public final LimitCommandContext limitCommand() throws RecognitionException {
		LimitCommandContext _localctx = new LimitCommandContext(_ctx, getState());
		enterRule(_localctx, 46, RULE_limitCommand);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(349);
			match(LIMIT);
			setState(350);
			match(INTEGER_LITERAL);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class SortCommandContext extends ParserRuleContext {
		public TerminalNode SORT() { return getToken(EsqlBaseParser.SORT, 0); }
		public List<OrderExpressionContext> orderExpression() {
			return getRuleContexts(OrderExpressionContext.class);
		}
		public OrderExpressionContext orderExpression(int i) {
			return getRuleContext(OrderExpressionContext.class,i);
		}
		public List<TerminalNode> COMMA() { return getTokens(EsqlBaseParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(EsqlBaseParser.COMMA, i);
		}
		public SortCommandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_sortCommand; }
	}

	public final SortCommandContext sortCommand() throws RecognitionException {
		SortCommandContext _localctx = new SortCommandContext(_ctx, getState());
		enterRule(_localctx, 48, RULE_sortCommand);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(352);
			match(SORT);
			setState(353);
			orderExpression();
			setState(358);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,32,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(354);
					match(COMMA);
					setState(355);
					orderExpression();
					}
					} 
				}
				setState(360);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,32,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class OrderExpressionContext extends ParserRuleContext {
		public Token ordering;
		public Token nullOrdering;
		public BooleanExpressionContext booleanExpression() {
			return getRuleContext(BooleanExpressionContext.class,0);
		}
		public TerminalNode NULLS() { return getToken(EsqlBaseParser.NULLS, 0); }
		public TerminalNode ASC() { return getToken(EsqlBaseParser.ASC, 0); }
		public TerminalNode DESC() { return getToken(EsqlBaseParser.DESC, 0); }
		public TerminalNode FIRST() { return getToken(EsqlBaseParser.FIRST, 0); }
		public TerminalNode LAST() { return getToken(EsqlBaseParser.LAST, 0); }
		public OrderExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_orderExpression; }
	}

	public final OrderExpressionContext orderExpression() throws RecognitionException {
		OrderExpressionContext _localctx = new OrderExpressionContext(_ctx, getState());
		enterRule(_localctx, 50, RULE_orderExpression);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(361);
			booleanExpression(0);
			setState(363);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,33,_ctx) ) {
			case 1:
				{
				setState(362);
				((OrderExpressionContext)_localctx).ordering = _input.LT(1);
				_la = _input.LA(1);
				if ( !(_la==ASC || _la==DESC) ) {
					((OrderExpressionContext)_localctx).ordering = (Token)_errHandler.recoverInline(this);
				}
				else {
					if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
					_errHandler.reportMatch(this);
					consume();
				}
				}
				break;
			}
			setState(367);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,34,_ctx) ) {
			case 1:
				{
				setState(365);
				match(NULLS);
				setState(366);
				((OrderExpressionContext)_localctx).nullOrdering = _input.LT(1);
				_la = _input.LA(1);
				if ( !(_la==FIRST || _la==LAST) ) {
					((OrderExpressionContext)_localctx).nullOrdering = (Token)_errHandler.recoverInline(this);
				}
				else {
					if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
					_errHandler.reportMatch(this);
					consume();
				}
				}
				break;
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class KeepCommandContext extends ParserRuleContext {
		public TerminalNode KEEP() { return getToken(EsqlBaseParser.KEEP, 0); }
		public List<SourceIdentifierContext> sourceIdentifier() {
			return getRuleContexts(SourceIdentifierContext.class);
		}
		public SourceIdentifierContext sourceIdentifier(int i) {
			return getRuleContext(SourceIdentifierContext.class,i);
		}
		public List<TerminalNode> COMMA() { return getTokens(EsqlBaseParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(EsqlBaseParser.COMMA, i);
		}
		public TerminalNode PROJECT() { return getToken(EsqlBaseParser.PROJECT, 0); }
		public KeepCommandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_keepCommand; }
	}

	public final KeepCommandContext keepCommand() throws RecognitionException {
		KeepCommandContext _localctx = new KeepCommandContext(_ctx, getState());
		enterRule(_localctx, 52, RULE_keepCommand);
		try {
			int _alt;
			setState(387);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case KEEP:
				enterOuterAlt(_localctx, 1);
				{
				setState(369);
				match(KEEP);
				setState(370);
				sourceIdentifier();
				setState(375);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,35,_ctx);
				while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
					if ( _alt==1 ) {
						{
						{
						setState(371);
						match(COMMA);
						setState(372);
						sourceIdentifier();
						}
						} 
					}
					setState(377);
					_errHandler.sync(this);
					_alt = getInterpreter().adaptivePredict(_input,35,_ctx);
				}
				}
				break;
			case PROJECT:
				enterOuterAlt(_localctx, 2);
				{
				setState(378);
				match(PROJECT);
				setState(379);
				sourceIdentifier();
				setState(384);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,36,_ctx);
				while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
					if ( _alt==1 ) {
						{
						{
						setState(380);
						match(COMMA);
						setState(381);
						sourceIdentifier();
						}
						} 
					}
					setState(386);
					_errHandler.sync(this);
					_alt = getInterpreter().adaptivePredict(_input,36,_ctx);
				}
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class DropCommandContext extends ParserRuleContext {
		public TerminalNode DROP() { return getToken(EsqlBaseParser.DROP, 0); }
		public List<SourceIdentifierContext> sourceIdentifier() {
			return getRuleContexts(SourceIdentifierContext.class);
		}
		public SourceIdentifierContext sourceIdentifier(int i) {
			return getRuleContext(SourceIdentifierContext.class,i);
		}
		public List<TerminalNode> COMMA() { return getTokens(EsqlBaseParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(EsqlBaseParser.COMMA, i);
		}
		public DropCommandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_dropCommand; }
	}

	public final DropCommandContext dropCommand() throws RecognitionException {
		DropCommandContext _localctx = new DropCommandContext(_ctx, getState());
		enterRule(_localctx, 54, RULE_dropCommand);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(389);
			match(DROP);
			setState(390);
			sourceIdentifier();
			setState(395);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,38,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(391);
					match(COMMA);
					setState(392);
					sourceIdentifier();
					}
					} 
				}
				setState(397);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,38,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class RenameCommandContext extends ParserRuleContext {
		public TerminalNode RENAME() { return getToken(EsqlBaseParser.RENAME, 0); }
		public List<RenameClauseContext> renameClause() {
			return getRuleContexts(RenameClauseContext.class);
		}
		public RenameClauseContext renameClause(int i) {
			return getRuleContext(RenameClauseContext.class,i);
		}
		public List<TerminalNode> COMMA() { return getTokens(EsqlBaseParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(EsqlBaseParser.COMMA, i);
		}
		public RenameCommandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_renameCommand; }
	}

	public final RenameCommandContext renameCommand() throws RecognitionException {
		RenameCommandContext _localctx = new RenameCommandContext(_ctx, getState());
		enterRule(_localctx, 56, RULE_renameCommand);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(398);
			match(RENAME);
			setState(399);
			renameClause();
			setState(404);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,39,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(400);
					match(COMMA);
					setState(401);
					renameClause();
					}
					} 
				}
				setState(406);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,39,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class RenameClauseContext extends ParserRuleContext {
		public SourceIdentifierContext oldName;
		public SourceIdentifierContext newName;
		public TerminalNode AS() { return getToken(EsqlBaseParser.AS, 0); }
		public List<SourceIdentifierContext> sourceIdentifier() {
			return getRuleContexts(SourceIdentifierContext.class);
		}
		public SourceIdentifierContext sourceIdentifier(int i) {
			return getRuleContext(SourceIdentifierContext.class,i);
		}
		public RenameClauseContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_renameClause; }
	}

	public final RenameClauseContext renameClause() throws RecognitionException {
		RenameClauseContext _localctx = new RenameClauseContext(_ctx, getState());
		enterRule(_localctx, 58, RULE_renameClause);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(407);
			((RenameClauseContext)_localctx).oldName = sourceIdentifier();
			setState(408);
			match(AS);
			setState(409);
			((RenameClauseContext)_localctx).newName = sourceIdentifier();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class DissectCommandContext extends ParserRuleContext {
		public TerminalNode DISSECT() { return getToken(EsqlBaseParser.DISSECT, 0); }
		public PrimaryExpressionContext primaryExpression() {
			return getRuleContext(PrimaryExpressionContext.class,0);
		}
		public StringContext string() {
			return getRuleContext(StringContext.class,0);
		}
		public CommandOptionsContext commandOptions() {
			return getRuleContext(CommandOptionsContext.class,0);
		}
		public DissectCommandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_dissectCommand; }
	}

	public final DissectCommandContext dissectCommand() throws RecognitionException {
		DissectCommandContext _localctx = new DissectCommandContext(_ctx, getState());
		enterRule(_localctx, 60, RULE_dissectCommand);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(411);
			match(DISSECT);
			setState(412);
			primaryExpression();
			setState(413);
			string();
			setState(415);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,40,_ctx) ) {
			case 1:
				{
				setState(414);
				commandOptions();
				}
				break;
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class GrokCommandContext extends ParserRuleContext {
		public TerminalNode GROK() { return getToken(EsqlBaseParser.GROK, 0); }
		public PrimaryExpressionContext primaryExpression() {
			return getRuleContext(PrimaryExpressionContext.class,0);
		}
		public StringContext string() {
			return getRuleContext(StringContext.class,0);
		}
		public GrokCommandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_grokCommand; }
	}

	public final GrokCommandContext grokCommand() throws RecognitionException {
		GrokCommandContext _localctx = new GrokCommandContext(_ctx, getState());
		enterRule(_localctx, 62, RULE_grokCommand);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(417);
			match(GROK);
			setState(418);
			primaryExpression();
			setState(419);
			string();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class MvExpandCommandContext extends ParserRuleContext {
		public TerminalNode MV_EXPAND() { return getToken(EsqlBaseParser.MV_EXPAND, 0); }
		public SourceIdentifierContext sourceIdentifier() {
			return getRuleContext(SourceIdentifierContext.class,0);
		}
		public MvExpandCommandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_mvExpandCommand; }
	}

	public final MvExpandCommandContext mvExpandCommand() throws RecognitionException {
		MvExpandCommandContext _localctx = new MvExpandCommandContext(_ctx, getState());
		enterRule(_localctx, 64, RULE_mvExpandCommand);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(421);
			match(MV_EXPAND);
			setState(422);
			sourceIdentifier();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class CommandOptionsContext extends ParserRuleContext {
		public List<CommandOptionContext> commandOption() {
			return getRuleContexts(CommandOptionContext.class);
		}
		public CommandOptionContext commandOption(int i) {
			return getRuleContext(CommandOptionContext.class,i);
		}
		public List<TerminalNode> COMMA() { return getTokens(EsqlBaseParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(EsqlBaseParser.COMMA, i);
		}
		public CommandOptionsContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_commandOptions; }
	}

	public final CommandOptionsContext commandOptions() throws RecognitionException {
		CommandOptionsContext _localctx = new CommandOptionsContext(_ctx, getState());
		enterRule(_localctx, 66, RULE_commandOptions);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(424);
			commandOption();
			setState(429);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,41,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(425);
					match(COMMA);
					setState(426);
					commandOption();
					}
					} 
				}
				setState(431);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,41,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class CommandOptionContext extends ParserRuleContext {
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public TerminalNode ASSIGN() { return getToken(EsqlBaseParser.ASSIGN, 0); }
		public ConstantContext constant() {
			return getRuleContext(ConstantContext.class,0);
		}
		public CommandOptionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_commandOption; }
	}

	public final CommandOptionContext commandOption() throws RecognitionException {
		CommandOptionContext _localctx = new CommandOptionContext(_ctx, getState());
		enterRule(_localctx, 68, RULE_commandOption);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(432);
			identifier();
			setState(433);
			match(ASSIGN);
			setState(434);
			constant();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class BooleanValueContext extends ParserRuleContext {
		public TerminalNode TRUE() { return getToken(EsqlBaseParser.TRUE, 0); }
		public TerminalNode FALSE() { return getToken(EsqlBaseParser.FALSE, 0); }
		public BooleanValueContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_booleanValue; }
	}

	public final BooleanValueContext booleanValue() throws RecognitionException {
		BooleanValueContext _localctx = new BooleanValueContext(_ctx, getState());
		enterRule(_localctx, 70, RULE_booleanValue);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(436);
			_la = _input.LA(1);
			if ( !(_la==FALSE || _la==TRUE) ) {
			_errHandler.recoverInline(this);
			}
			else {
				if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
				_errHandler.reportMatch(this);
				consume();
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class NumericValueContext extends ParserRuleContext {
		public DecimalValueContext decimalValue() {
			return getRuleContext(DecimalValueContext.class,0);
		}
		public IntegerValueContext integerValue() {
			return getRuleContext(IntegerValueContext.class,0);
		}
		public NumericValueContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_numericValue; }
	}

	public final NumericValueContext numericValue() throws RecognitionException {
		NumericValueContext _localctx = new NumericValueContext(_ctx, getState());
		enterRule(_localctx, 72, RULE_numericValue);
		try {
			setState(440);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case DECIMAL_LITERAL:
				enterOuterAlt(_localctx, 1);
				{
				setState(438);
				decimalValue();
				}
				break;
			case INTEGER_LITERAL:
				enterOuterAlt(_localctx, 2);
				{
				setState(439);
				integerValue();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class DecimalValueContext extends ParserRuleContext {
		public TerminalNode DECIMAL_LITERAL() { return getToken(EsqlBaseParser.DECIMAL_LITERAL, 0); }
		public DecimalValueContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_decimalValue; }
	}

	public final DecimalValueContext decimalValue() throws RecognitionException {
		DecimalValueContext _localctx = new DecimalValueContext(_ctx, getState());
		enterRule(_localctx, 74, RULE_decimalValue);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(442);
			match(DECIMAL_LITERAL);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class IntegerValueContext extends ParserRuleContext {
		public TerminalNode INTEGER_LITERAL() { return getToken(EsqlBaseParser.INTEGER_LITERAL, 0); }
		public IntegerValueContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_integerValue; }
	}

	public final IntegerValueContext integerValue() throws RecognitionException {
		IntegerValueContext _localctx = new IntegerValueContext(_ctx, getState());
		enterRule(_localctx, 76, RULE_integerValue);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(444);
			match(INTEGER_LITERAL);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class StringContext extends ParserRuleContext {
		public TerminalNode STRING() { return getToken(EsqlBaseParser.STRING, 0); }
		public StringContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_string; }
	}

	public final StringContext string() throws RecognitionException {
		StringContext _localctx = new StringContext(_ctx, getState());
		enterRule(_localctx, 78, RULE_string);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(446);
			match(STRING);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ComparisonOperatorContext extends ParserRuleContext {
		public TerminalNode EQ() { return getToken(EsqlBaseParser.EQ, 0); }
		public TerminalNode NEQ() { return getToken(EsqlBaseParser.NEQ, 0); }
		public TerminalNode LT() { return getToken(EsqlBaseParser.LT, 0); }
		public TerminalNode LTE() { return getToken(EsqlBaseParser.LTE, 0); }
		public TerminalNode GT() { return getToken(EsqlBaseParser.GT, 0); }
		public TerminalNode GTE() { return getToken(EsqlBaseParser.GTE, 0); }
		public ComparisonOperatorContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_comparisonOperator; }
	}

	public final ComparisonOperatorContext comparisonOperator() throws RecognitionException {
		ComparisonOperatorContext _localctx = new ComparisonOperatorContext(_ctx, getState());
		enterRule(_localctx, 80, RULE_comparisonOperator);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(448);
			_la = _input.LA(1);
			if ( !((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << EQ) | (1L << NEQ) | (1L << LT) | (1L << LTE) | (1L << GT) | (1L << GTE))) != 0)) ) {
			_errHandler.recoverInline(this);
			}
			else {
				if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
				_errHandler.reportMatch(this);
				consume();
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ExplainCommandContext extends ParserRuleContext {
		public TerminalNode EXPLAIN() { return getToken(EsqlBaseParser.EXPLAIN, 0); }
		public SubqueryExpressionContext subqueryExpression() {
			return getRuleContext(SubqueryExpressionContext.class,0);
		}
		public ExplainCommandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_explainCommand; }
	}

	public final ExplainCommandContext explainCommand() throws RecognitionException {
		ExplainCommandContext _localctx = new ExplainCommandContext(_ctx, getState());
		enterRule(_localctx, 82, RULE_explainCommand);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(450);
			match(EXPLAIN);
			setState(451);
			subqueryExpression();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class SubqueryExpressionContext extends ParserRuleContext {
		public TerminalNode OPENING_BRACKET() { return getToken(EsqlBaseParser.OPENING_BRACKET, 0); }
		public QueryContext query() {
			return getRuleContext(QueryContext.class,0);
		}
		public TerminalNode CLOSING_BRACKET() { return getToken(EsqlBaseParser.CLOSING_BRACKET, 0); }
		public SubqueryExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_subqueryExpression; }
	}

	public final SubqueryExpressionContext subqueryExpression() throws RecognitionException {
		SubqueryExpressionContext _localctx = new SubqueryExpressionContext(_ctx, getState());
		enterRule(_localctx, 84, RULE_subqueryExpression);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(453);
			match(OPENING_BRACKET);
			setState(454);
			query(0);
			setState(455);
			match(CLOSING_BRACKET);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ShowCommandContext extends ParserRuleContext {
		public ShowCommandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_showCommand; }
	 
		public ShowCommandContext() { }
		public void copyFrom(ShowCommandContext ctx) {
			super.copyFrom(ctx);
		}
	}
	public static class ShowInfoContext extends ShowCommandContext {
		public TerminalNode SHOW() { return getToken(EsqlBaseParser.SHOW, 0); }
		public TerminalNode INFO() { return getToken(EsqlBaseParser.INFO, 0); }
		public ShowInfoContext(ShowCommandContext ctx) { copyFrom(ctx); }
	}
	public static class ShowFunctionsContext extends ShowCommandContext {
		public TerminalNode SHOW() { return getToken(EsqlBaseParser.SHOW, 0); }
		public TerminalNode FUNCTIONS() { return getToken(EsqlBaseParser.FUNCTIONS, 0); }
		public ShowFunctionsContext(ShowCommandContext ctx) { copyFrom(ctx); }
	}

	public final ShowCommandContext showCommand() throws RecognitionException {
		ShowCommandContext _localctx = new ShowCommandContext(_ctx, getState());
		enterRule(_localctx, 86, RULE_showCommand);
		try {
			setState(461);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,43,_ctx) ) {
			case 1:
				_localctx = new ShowInfoContext(_localctx);
				enterOuterAlt(_localctx, 1);
				{
				setState(457);
				match(SHOW);
				setState(458);
				match(INFO);
				}
				break;
			case 2:
				_localctx = new ShowFunctionsContext(_localctx);
				enterOuterAlt(_localctx, 2);
				{
				setState(459);
				match(SHOW);
				setState(460);
				match(FUNCTIONS);
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class EnrichCommandContext extends ParserRuleContext {
		public SourceIdentifierContext policyName;
		public SourceIdentifierContext matchField;
		public TerminalNode ENRICH() { return getToken(EsqlBaseParser.ENRICH, 0); }
		public List<SourceIdentifierContext> sourceIdentifier() {
			return getRuleContexts(SourceIdentifierContext.class);
		}
		public SourceIdentifierContext sourceIdentifier(int i) {
			return getRuleContext(SourceIdentifierContext.class,i);
		}
		public TerminalNode ON() { return getToken(EsqlBaseParser.ON, 0); }
		public TerminalNode WITH() { return getToken(EsqlBaseParser.WITH, 0); }
		public List<EnrichWithClauseContext> enrichWithClause() {
			return getRuleContexts(EnrichWithClauseContext.class);
		}
		public EnrichWithClauseContext enrichWithClause(int i) {
			return getRuleContext(EnrichWithClauseContext.class,i);
		}
		public List<TerminalNode> COMMA() { return getTokens(EsqlBaseParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(EsqlBaseParser.COMMA, i);
		}
		public EnrichCommandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_enrichCommand; }
	}

	public final EnrichCommandContext enrichCommand() throws RecognitionException {
		EnrichCommandContext _localctx = new EnrichCommandContext(_ctx, getState());
		enterRule(_localctx, 88, RULE_enrichCommand);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(463);
			match(ENRICH);
			setState(464);
			((EnrichCommandContext)_localctx).policyName = sourceIdentifier();
			setState(467);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,44,_ctx) ) {
			case 1:
				{
				setState(465);
				match(ON);
				setState(466);
				((EnrichCommandContext)_localctx).matchField = sourceIdentifier();
				}
				break;
			}
			setState(478);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,46,_ctx) ) {
			case 1:
				{
				setState(469);
				match(WITH);
				setState(470);
				enrichWithClause();
				setState(475);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,45,_ctx);
				while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
					if ( _alt==1 ) {
						{
						{
						setState(471);
						match(COMMA);
						setState(472);
						enrichWithClause();
						}
						} 
					}
					setState(477);
					_errHandler.sync(this);
					_alt = getInterpreter().adaptivePredict(_input,45,_ctx);
				}
				}
				break;
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class EnrichWithClauseContext extends ParserRuleContext {
		public SourceIdentifierContext newName;
		public SourceIdentifierContext enrichField;
		public List<SourceIdentifierContext> sourceIdentifier() {
			return getRuleContexts(SourceIdentifierContext.class);
		}
		public SourceIdentifierContext sourceIdentifier(int i) {
			return getRuleContext(SourceIdentifierContext.class,i);
		}
		public TerminalNode ASSIGN() { return getToken(EsqlBaseParser.ASSIGN, 0); }
		public EnrichWithClauseContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_enrichWithClause; }
	}

	public final EnrichWithClauseContext enrichWithClause() throws RecognitionException {
		EnrichWithClauseContext _localctx = new EnrichWithClauseContext(_ctx, getState());
		enterRule(_localctx, 90, RULE_enrichWithClause);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(483);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,47,_ctx) ) {
			case 1:
				{
				setState(480);
				((EnrichWithClauseContext)_localctx).newName = sourceIdentifier();
				setState(481);
				match(ASSIGN);
				}
				break;
			}
			setState(485);
			((EnrichWithClauseContext)_localctx).enrichField = sourceIdentifier();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public boolean sempred(RuleContext _localctx, int ruleIndex, int predIndex) {
		switch (ruleIndex) {
		case 1:
			return query_sempred((QueryContext)_localctx, predIndex);
		case 5:
			return booleanExpression_sempred((BooleanExpressionContext)_localctx, predIndex);
		case 8:
			return operatorExpression_sempred((OperatorExpressionContext)_localctx, predIndex);
		}
		return true;
	}
	private boolean query_sempred(QueryContext _localctx, int predIndex) {
		switch (predIndex) {
		case 0:
			return precpred(_ctx, 1);
		}
		return true;
	}
	private boolean booleanExpression_sempred(BooleanExpressionContext _localctx, int predIndex) {
		switch (predIndex) {
		case 1:
			return precpred(_ctx, 3);
		case 2:
			return precpred(_ctx, 2);
		}
		return true;
	}
	private boolean operatorExpression_sempred(OperatorExpressionContext _localctx, int predIndex) {
		switch (predIndex) {
		case 3:
			return precpred(_ctx, 2);
		case 4:
			return precpred(_ctx, 1);
		}
		return true;
	}

	public static final String _serializedATN =
		"\3\u608b\ua72a\u8133\ub9ed\u417c\u3be7\u7786\u5964\3R\u01ea\4\2\t\2\4"+
		"\3\t\3\4\4\t\4\4\5\t\5\4\6\t\6\4\7\t\7\4\b\t\b\4\t\t\t\4\n\t\n\4\13\t"+
		"\13\4\f\t\f\4\r\t\r\4\16\t\16\4\17\t\17\4\20\t\20\4\21\t\21\4\22\t\22"+
		"\4\23\t\23\4\24\t\24\4\25\t\25\4\26\t\26\4\27\t\27\4\30\t\30\4\31\t\31"+
		"\4\32\t\32\4\33\t\33\4\34\t\34\4\35\t\35\4\36\t\36\4\37\t\37\4 \t \4!"+
		"\t!\4\"\t\"\4#\t#\4$\t$\4%\t%\4&\t&\4\'\t\'\4(\t(\4)\t)\4*\t*\4+\t+\4"+
		",\t,\4-\t-\4.\t.\4/\t/\3\2\3\2\3\2\3\3\3\3\3\3\3\3\3\3\3\3\7\3h\n\3\f"+
		"\3\16\3k\13\3\3\4\3\4\3\4\3\4\5\4q\n\4\3\5\3\5\3\5\3\5\3\5\3\5\3\5\3\5"+
		"\3\5\3\5\3\5\3\5\3\5\5\5\u0080\n\5\3\6\3\6\3\6\3\7\3\7\3\7\3\7\3\7\3\7"+
		"\3\7\5\7\u008c\n\7\3\7\3\7\3\7\3\7\3\7\7\7\u0093\n\7\f\7\16\7\u0096\13"+
		"\7\3\7\3\7\5\7\u009a\n\7\3\7\3\7\3\7\3\7\3\7\3\7\7\7\u00a2\n\7\f\7\16"+
		"\7\u00a5\13\7\3\b\3\b\5\b\u00a9\n\b\3\b\3\b\3\b\3\b\3\b\5\b\u00b0\n\b"+
		"\3\b\3\b\3\b\5\b\u00b5\n\b\3\t\3\t\3\t\3\t\3\t\5\t\u00bc\n\t\3\n\3\n\3"+
		"\n\3\n\5\n\u00c2\n\n\3\n\3\n\3\n\3\n\3\n\3\n\7\n\u00ca\n\n\f\n\16\n\u00cd"+
		"\13\n\3\13\3\13\3\13\3\13\3\13\3\13\3\13\3\13\3\13\3\13\3\13\7\13\u00da"+
		"\n\13\f\13\16\13\u00dd\13\13\5\13\u00df\n\13\3\13\3\13\5\13\u00e3\n\13"+
		"\3\f\3\f\3\f\3\r\3\r\3\r\7\r\u00eb\n\r\f\r\16\r\u00ee\13\r\3\16\3\16\3"+
		"\16\3\16\3\16\5\16\u00f5\n\16\3\17\3\17\3\17\3\17\7\17\u00fb\n\17\f\17"+
		"\16\17\u00fe\13\17\3\17\5\17\u0101\n\17\3\20\3\20\3\20\3\20\3\20\7\20"+
		"\u0108\n\20\f\20\16\20\u010b\13\20\3\20\3\20\3\21\3\21\3\21\3\22\3\22"+
		"\5\22\u0114\n\22\3\22\3\22\5\22\u0118\n\22\3\23\3\23\3\23\3\23\5\23\u011e"+
		"\n\23\3\24\3\24\3\24\7\24\u0123\n\24\f\24\16\24\u0126\13\24\3\25\3\25"+
		"\3\26\3\26\3\26\7\26\u012d\n\26\f\26\16\26\u0130\13\26\3\27\3\27\3\30"+
		"\3\30\3\30\3\30\3\30\3\30\3\30\3\30\3\30\3\30\3\30\3\30\3\30\7\30\u0141"+
		"\n\30\f\30\16\30\u0144\13\30\3\30\3\30\3\30\3\30\3\30\3\30\7\30\u014c"+
		"\n\30\f\30\16\30\u014f\13\30\3\30\3\30\3\30\3\30\3\30\3\30\7\30\u0157"+
		"\n\30\f\30\16\30\u015a\13\30\3\30\3\30\5\30\u015e\n\30\3\31\3\31\3\31"+
		"\3\32\3\32\3\32\3\32\7\32\u0167\n\32\f\32\16\32\u016a\13\32\3\33\3\33"+
		"\5\33\u016e\n\33\3\33\3\33\5\33\u0172\n\33\3\34\3\34\3\34\3\34\7\34\u0178"+
		"\n\34\f\34\16\34\u017b\13\34\3\34\3\34\3\34\3\34\7\34\u0181\n\34\f\34"+
		"\16\34\u0184\13\34\5\34\u0186\n\34\3\35\3\35\3\35\3\35\7\35\u018c\n\35"+
		"\f\35\16\35\u018f\13\35\3\36\3\36\3\36\3\36\7\36\u0195\n\36\f\36\16\36"+
		"\u0198\13\36\3\37\3\37\3\37\3\37\3 \3 \3 \3 \5 \u01a2\n \3!\3!\3!\3!\3"+
		"\"\3\"\3\"\3#\3#\3#\7#\u01ae\n#\f#\16#\u01b1\13#\3$\3$\3$\3$\3%\3%\3&"+
		"\3&\5&\u01bb\n&\3\'\3\'\3(\3(\3)\3)\3*\3*\3+\3+\3+\3,\3,\3,\3,\3-\3-\3"+
		"-\3-\5-\u01d0\n-\3.\3.\3.\3.\5.\u01d6\n.\3.\3.\3.\3.\7.\u01dc\n.\f.\16"+
		".\u01df\13.\5.\u01e1\n.\3/\3/\3/\5/\u01e6\n/\3/\3/\3/\2\5\4\f\22\60\2"+
		"\4\6\b\n\f\16\20\22\24\26\30\32\34\36 \"$&(*,.\60\62\64\668:<>@BDFHJL"+
		"NPRTVXZ\\\2\n\3\2=>\3\2?A\3\2MN\3\2DE\4\2\"\"%%\3\2()\4\2\'\'\64\64\3"+
		"\2\67<\2\u0204\2^\3\2\2\2\4a\3\2\2\2\6p\3\2\2\2\b\177\3\2\2\2\n\u0081"+
		"\3\2\2\2\f\u0099\3\2\2\2\16\u00b4\3\2\2\2\20\u00bb\3\2\2\2\22\u00c1\3"+
		"\2\2\2\24\u00e2\3\2\2\2\26\u00e4\3\2\2\2\30\u00e7\3\2\2\2\32\u00f4\3\2"+
		"\2\2\34\u00f6\3\2\2\2\36\u0102\3\2\2\2 \u010e\3\2\2\2\"\u0111\3\2\2\2"+
		"$\u0119\3\2\2\2&\u011f\3\2\2\2(\u0127\3\2\2\2*\u0129\3\2\2\2,\u0131\3"+
		"\2\2\2.\u015d\3\2\2\2\60\u015f\3\2\2\2\62\u0162\3\2\2\2\64\u016b\3\2\2"+
		"\2\66\u0185\3\2\2\28\u0187\3\2\2\2:\u0190\3\2\2\2<\u0199\3\2\2\2>\u019d"+
		"\3\2\2\2@\u01a3\3\2\2\2B\u01a7\3\2\2\2D\u01aa\3\2\2\2F\u01b2\3\2\2\2H"+
		"\u01b6\3\2\2\2J\u01ba\3\2\2\2L\u01bc\3\2\2\2N\u01be\3\2\2\2P\u01c0\3\2"+
		"\2\2R\u01c2\3\2\2\2T\u01c4\3\2\2\2V\u01c7\3\2\2\2X\u01cf\3\2\2\2Z\u01d1"+
		"\3\2\2\2\\\u01e5\3\2\2\2^_\5\4\3\2_`\7\2\2\3`\3\3\2\2\2ab\b\3\1\2bc\5"+
		"\6\4\2ci\3\2\2\2de\f\3\2\2ef\7\34\2\2fh\5\b\5\2gd\3\2\2\2hk\3\2\2\2ig"+
		"\3\2\2\2ij\3\2\2\2j\5\3\2\2\2ki\3\2\2\2lq\5T+\2mq\5\34\17\2nq\5\26\f\2"+
		"oq\5X-\2pl\3\2\2\2pm\3\2\2\2pn\3\2\2\2po\3\2\2\2q\7\3\2\2\2r\u0080\5 "+
		"\21\2s\u0080\5$\23\2t\u0080\5\60\31\2u\u0080\5\66\34\2v\u0080\5\62\32"+
		"\2w\u0080\5\"\22\2x\u0080\5\n\6\2y\u0080\58\35\2z\u0080\5:\36\2{\u0080"+
		"\5> \2|\u0080\5@!\2}\u0080\5Z.\2~\u0080\5B\"\2\177r\3\2\2\2\177s\3\2\2"+
		"\2\177t\3\2\2\2\177u\3\2\2\2\177v\3\2\2\2\177w\3\2\2\2\177x\3\2\2\2\177"+
		"y\3\2\2\2\177z\3\2\2\2\177{\3\2\2\2\177|\3\2\2\2\177}\3\2\2\2\177~\3\2"+
		"\2\2\u0080\t\3\2\2\2\u0081\u0082\7\24\2\2\u0082\u0083\5\f\7\2\u0083\13"+
		"\3\2\2\2\u0084\u0085\b\7\1\2\u0085\u0086\7-\2\2\u0086\u009a\5\f\7\b\u0087"+
		"\u009a\5\20\t\2\u0088\u009a\5\16\b\2\u0089\u008b\5\20\t\2\u008a\u008c"+
		"\7-\2\2\u008b\u008a\3\2\2\2\u008b\u008c\3\2\2\2\u008c\u008d\3\2\2\2\u008d"+
		"\u008e\7+\2\2\u008e\u008f\7*\2\2\u008f\u0094\5\20\t\2\u0090\u0091\7$\2"+
		"\2\u0091\u0093\5\20\t\2\u0092\u0090\3\2\2\2\u0093\u0096\3\2\2\2\u0094"+
		"\u0092\3\2\2\2\u0094\u0095\3\2\2\2\u0095\u0097\3\2\2\2\u0096\u0094\3\2"+
		"\2\2\u0097\u0098\7\63\2\2\u0098\u009a\3\2\2\2\u0099\u0084\3\2\2\2\u0099"+
		"\u0087\3\2\2\2\u0099\u0088\3\2\2\2\u0099\u0089\3\2\2\2\u009a\u00a3\3\2"+
		"\2\2\u009b\u009c\f\5\2\2\u009c\u009d\7!\2\2\u009d\u00a2\5\f\7\6\u009e"+
		"\u009f\f\4\2\2\u009f\u00a0\7\60\2\2\u00a0\u00a2\5\f\7\5\u00a1\u009b\3"+
		"\2\2\2\u00a1\u009e\3\2\2\2\u00a2\u00a5\3\2\2\2\u00a3\u00a1\3\2\2\2\u00a3"+
		"\u00a4\3\2\2\2\u00a4\r\3\2\2\2\u00a5\u00a3\3\2\2\2\u00a6\u00a8\5\20\t"+
		"\2\u00a7\u00a9\7-\2\2\u00a8\u00a7\3\2\2\2\u00a8\u00a9\3\2\2\2\u00a9\u00aa"+
		"\3\2\2\2\u00aa\u00ab\7,\2\2\u00ab\u00ac\5P)\2\u00ac\u00b5\3\2\2\2\u00ad"+
		"\u00af\5\20\t\2\u00ae\u00b0\7-\2\2\u00af\u00ae\3\2\2\2\u00af\u00b0\3\2"+
		"\2\2\u00b0\u00b1\3\2\2\2\u00b1\u00b2\7\62\2\2\u00b2\u00b3\5P)\2\u00b3"+
		"\u00b5\3\2\2\2\u00b4\u00a6\3\2\2\2\u00b4\u00ad\3\2\2\2\u00b5\17\3\2\2"+
		"\2\u00b6\u00bc\5\22\n\2\u00b7\u00b8\5\22\n\2\u00b8\u00b9\5R*\2\u00b9\u00ba"+
		"\5\22\n\2\u00ba\u00bc\3\2\2\2\u00bb\u00b6\3\2\2\2\u00bb\u00b7\3\2\2\2"+
		"\u00bc\21\3\2\2\2\u00bd\u00be\b\n\1\2\u00be\u00c2\5\24\13\2\u00bf\u00c0"+
		"\t\2\2\2\u00c0\u00c2\5\22\n\5\u00c1\u00bd\3\2\2\2\u00c1\u00bf\3\2\2\2"+
		"\u00c2\u00cb\3\2\2\2\u00c3\u00c4\f\4\2\2\u00c4\u00c5\t\3\2\2\u00c5\u00ca"+
		"\5\22\n\5\u00c6\u00c7\f\3\2\2\u00c7\u00c8\t\2\2\2\u00c8\u00ca\5\22\n\4"+
		"\u00c9\u00c3\3\2\2\2\u00c9\u00c6\3\2\2\2\u00ca\u00cd\3\2\2\2\u00cb\u00c9"+
		"\3\2\2\2\u00cb\u00cc\3\2\2\2\u00cc\23\3\2\2\2\u00cd\u00cb\3\2\2\2\u00ce"+
		"\u00e3\5.\30\2\u00cf\u00e3\5*\26\2\u00d0\u00d1\7*\2\2\u00d1\u00d2\5\f"+
		"\7\2\u00d2\u00d3\7\63\2\2\u00d3\u00e3\3\2\2\2\u00d4\u00d5\5,\27\2\u00d5"+
		"\u00de\7*\2\2\u00d6\u00db\5\f\7\2\u00d7\u00d8\7$\2\2\u00d8\u00da\5\f\7"+
		"\2\u00d9\u00d7\3\2\2\2\u00da\u00dd\3\2\2\2\u00db\u00d9\3\2\2\2\u00db\u00dc"+
		"\3\2\2\2\u00dc\u00df\3\2\2\2\u00dd\u00db\3\2\2\2\u00de\u00d6\3\2\2\2\u00de"+
		"\u00df\3\2\2\2\u00df\u00e0\3\2\2\2\u00e0\u00e1\7\63\2\2\u00e1\u00e3\3"+
		"\2\2\2\u00e2\u00ce\3\2\2\2\u00e2\u00cf\3\2\2\2\u00e2\u00d0\3\2\2\2\u00e2"+
		"\u00d4\3\2\2\2\u00e3\25\3\2\2\2\u00e4\u00e5\7\20\2\2\u00e5\u00e6\5\30"+
		"\r\2\u00e6\27\3\2\2\2\u00e7\u00ec\5\32\16\2\u00e8\u00e9\7$\2\2\u00e9\u00eb"+
		"\5\32\16\2\u00ea\u00e8\3\2\2\2\u00eb\u00ee\3\2\2\2\u00ec\u00ea\3\2\2\2"+
		"\u00ec\u00ed\3\2\2\2\u00ed\31\3\2\2\2\u00ee\u00ec\3\2\2\2\u00ef\u00f5"+
		"\5\f\7\2\u00f0\u00f1\5*\26\2\u00f1\u00f2\7#\2\2\u00f2\u00f3\5\f\7\2\u00f3"+
		"\u00f5\3\2\2\2\u00f4\u00ef\3\2\2\2\u00f4\u00f0\3\2\2\2\u00f5\33\3\2\2"+
		"\2\u00f6\u00f7\7\b\2\2\u00f7\u00fc\5(\25\2\u00f8\u00f9\7$\2\2\u00f9\u00fb"+
		"\5(\25\2\u00fa\u00f8\3\2\2\2\u00fb\u00fe\3\2\2\2\u00fc\u00fa\3\2\2\2\u00fc"+
		"\u00fd\3\2\2\2\u00fd\u0100\3\2\2\2\u00fe\u00fc\3\2\2\2\u00ff\u0101\5\36"+
		"\20\2\u0100\u00ff\3\2\2\2\u0100\u0101\3\2\2\2\u0101\35\3\2\2\2\u0102\u0103"+
		"\7B\2\2\u0103\u0104\7J\2\2\u0104\u0109\5(\25\2\u0105\u0106\7$\2\2\u0106"+
		"\u0108\5(\25\2\u0107\u0105\3\2\2\2\u0108\u010b\3\2\2\2\u0109\u0107\3\2"+
		"\2\2\u0109\u010a\3\2\2\2\u010a\u010c\3\2\2\2\u010b\u0109\3\2\2\2\u010c"+
		"\u010d\7C\2\2\u010d\37\3\2\2\2\u010e\u010f\7\6\2\2\u010f\u0110\5\30\r"+
		"\2\u0110!\3\2\2\2\u0111\u0113\7\23\2\2\u0112\u0114\5\30\r\2\u0113\u0112"+
		"\3\2\2\2\u0113\u0114\3\2\2\2\u0114\u0117\3\2\2\2\u0115\u0116\7 \2\2\u0116"+
		"\u0118\5&\24\2\u0117\u0115\3\2\2\2\u0117\u0118\3\2\2\2\u0118#\3\2\2\2"+
		"\u0119\u011a\7\n\2\2\u011a\u011d\5\30\r\2\u011b\u011c\7 \2\2\u011c\u011e"+
		"\5&\24\2\u011d\u011b\3\2\2\2\u011d\u011e\3\2\2\2\u011e%\3\2\2\2\u011f"+
		"\u0124\5*\26\2\u0120\u0121\7$\2\2\u0121\u0123\5*\26\2\u0122\u0120\3\2"+
		"\2\2\u0123\u0126\3\2\2\2\u0124\u0122\3\2\2\2\u0124\u0125\3\2\2\2\u0125"+
		"\'\3\2\2\2\u0126\u0124\3\2\2\2\u0127\u0128\t\4\2\2\u0128)\3\2\2\2\u0129"+
		"\u012e\5,\27\2\u012a\u012b\7&\2\2\u012b\u012d\5,\27\2\u012c\u012a\3\2"+
		"\2\2\u012d\u0130\3\2\2\2\u012e\u012c\3\2\2\2\u012e\u012f\3\2\2\2\u012f"+
		"+\3\2\2\2\u0130\u012e\3\2\2\2\u0131\u0132\t\5\2\2\u0132-\3\2\2\2\u0133"+
		"\u015e\7.\2\2\u0134\u0135\5N(\2\u0135\u0136\7D\2\2\u0136\u015e\3\2\2\2"+
		"\u0137\u015e\5L\'\2\u0138\u015e\5N(\2\u0139\u015e\5H%\2\u013a\u015e\7"+
		"\61\2\2\u013b\u015e\5P)\2\u013c\u013d\7B\2\2\u013d\u0142\5J&\2\u013e\u013f"+
		"\7$\2\2\u013f\u0141\5J&\2\u0140\u013e\3\2\2\2\u0141\u0144\3\2\2\2\u0142"+
		"\u0140\3\2\2\2\u0142\u0143\3\2\2\2\u0143\u0145\3\2\2\2\u0144\u0142\3\2"+
		"\2\2\u0145\u0146\7C\2\2\u0146\u015e\3\2\2\2\u0147\u0148\7B\2\2\u0148\u014d"+
		"\5H%\2\u0149\u014a\7$\2\2\u014a\u014c\5H%\2\u014b\u0149\3\2\2\2\u014c"+
		"\u014f\3\2\2\2\u014d\u014b\3\2\2\2\u014d\u014e\3\2\2\2\u014e\u0150\3\2"+
		"\2\2\u014f\u014d\3\2\2\2\u0150\u0151\7C\2\2\u0151\u015e\3\2\2\2\u0152"+
		"\u0153\7B\2\2\u0153\u0158\5P)\2\u0154\u0155\7$\2\2\u0155\u0157\5P)\2\u0156"+
		"\u0154\3\2\2\2\u0157\u015a\3\2\2\2\u0158\u0156\3\2\2\2\u0158\u0159\3\2"+
		"\2\2\u0159\u015b\3\2\2\2\u015a\u0158\3\2\2\2\u015b\u015c\7C\2\2\u015c"+
		"\u015e\3\2\2\2\u015d\u0133\3\2\2\2\u015d\u0134\3\2\2\2\u015d\u0137\3\2"+
		"\2\2\u015d\u0138\3\2\2\2\u015d\u0139\3\2\2\2\u015d\u013a\3\2\2\2\u015d"+
		"\u013b\3\2\2\2\u015d\u013c\3\2\2\2\u015d\u0147\3\2\2\2\u015d\u0152\3\2"+
		"\2\2\u015e/\3\2\2\2\u015f\u0160\7\f\2\2\u0160\u0161\7\36\2\2\u0161\61"+
		"\3\2\2\2\u0162\u0163\7\22\2\2\u0163\u0168\5\64\33\2\u0164\u0165\7$\2\2"+
		"\u0165\u0167\5\64\33\2\u0166\u0164\3\2\2\2\u0167\u016a\3\2\2\2\u0168\u0166"+
		"\3\2\2\2\u0168\u0169\3\2\2\2\u0169\63\3\2\2\2\u016a\u0168\3\2\2\2\u016b"+
		"\u016d\5\f\7\2\u016c\u016e\t\6\2\2\u016d\u016c\3\2\2\2\u016d\u016e\3\2"+
		"\2\2\u016e\u0171\3\2\2\2\u016f\u0170\7/\2\2\u0170\u0172\t\7\2\2\u0171"+
		"\u016f\3\2\2\2\u0171\u0172\3\2\2\2\u0172\65\3\2\2\2\u0173\u0174\7\13\2"+
		"\2\u0174\u0179\5(\25\2\u0175\u0176\7$\2\2\u0176\u0178\5(\25\2\u0177\u0175"+
		"\3\2\2\2\u0178\u017b\3\2\2\2\u0179\u0177\3\2\2\2\u0179\u017a\3\2\2\2\u017a"+
		"\u0186\3\2\2\2\u017b\u0179\3\2\2\2\u017c\u017d\7\16\2\2\u017d\u0182\5"+
		"(\25\2\u017e\u017f\7$\2\2\u017f\u0181\5(\25\2\u0180\u017e\3\2\2\2\u0181"+
		"\u0184\3\2\2\2\u0182\u0180\3\2\2\2\u0182\u0183\3\2\2\2\u0183\u0186\3\2"+
		"\2\2\u0184\u0182\3\2\2\2\u0185\u0173\3\2\2\2\u0185\u017c\3\2\2\2\u0186"+
		"\67\3\2\2\2\u0187\u0188\7\4\2\2\u0188\u018d\5(\25\2\u0189\u018a\7$\2\2"+
		"\u018a\u018c\5(\25\2\u018b\u0189\3\2\2\2\u018c\u018f\3\2\2\2\u018d\u018b"+
		"\3\2\2\2\u018d\u018e\3\2\2\2\u018e9\3\2\2\2\u018f\u018d\3\2\2\2\u0190"+
		"\u0191\7\17\2\2\u0191\u0196\5<\37\2\u0192\u0193\7$\2\2\u0193\u0195\5<"+
		"\37\2\u0194\u0192\3\2\2\2\u0195\u0198\3\2\2\2\u0196\u0194\3\2\2\2\u0196"+
		"\u0197\3\2\2\2\u0197;\3\2\2\2\u0198\u0196\3\2\2\2\u0199\u019a\5(\25\2"+
		"\u019a\u019b\7I\2\2\u019b\u019c\5(\25\2\u019c=\3\2\2\2\u019d\u019e\7\3"+
		"\2\2\u019e\u019f\5\24\13\2\u019f\u01a1\5P)\2\u01a0\u01a2\5D#\2\u01a1\u01a0"+
		"\3\2\2\2\u01a1\u01a2\3\2\2\2\u01a2?\3\2\2\2\u01a3\u01a4\7\t\2\2\u01a4"+
		"\u01a5\5\24\13\2\u01a5\u01a6\5P)\2\u01a6A\3\2\2\2\u01a7\u01a8\7\r\2\2"+
		"\u01a8\u01a9\5(\25\2\u01a9C\3\2\2\2\u01aa\u01af\5F$\2\u01ab\u01ac\7$\2"+
		"\2\u01ac\u01ae\5F$\2\u01ad\u01ab\3\2\2\2\u01ae\u01b1\3\2\2\2\u01af\u01ad"+
		"\3\2\2\2\u01af\u01b0\3\2\2\2\u01b0E\3\2\2\2\u01b1\u01af\3\2\2\2\u01b2"+
		"\u01b3\5,\27\2\u01b3\u01b4\7#\2\2\u01b4\u01b5\5.\30\2\u01b5G\3\2\2\2\u01b6"+
		"\u01b7\t\b\2\2\u01b7I\3\2\2\2\u01b8\u01bb\5L\'\2\u01b9\u01bb\5N(\2\u01ba"+
		"\u01b8\3\2\2\2\u01ba\u01b9\3\2\2\2\u01bbK\3\2\2\2\u01bc\u01bd\7\37\2\2"+
		"\u01bdM\3\2\2\2\u01be\u01bf\7\36\2\2\u01bfO\3\2\2\2\u01c0\u01c1\7\35\2"+
		"\2\u01c1Q\3\2\2\2\u01c2\u01c3\t\t\2\2\u01c3S\3\2\2\2\u01c4\u01c5\7\7\2"+
		"\2\u01c5\u01c6\5V,\2\u01c6U\3\2\2\2\u01c7\u01c8\7B\2\2\u01c8\u01c9\5\4"+
		"\3\2\u01c9\u01ca\7C\2\2\u01caW\3\2\2\2\u01cb\u01cc\7\21\2\2\u01cc\u01d0"+
		"\7\65\2\2\u01cd\u01ce\7\21\2\2\u01ce\u01d0\7\66\2\2\u01cf\u01cb\3\2\2"+
		"\2\u01cf\u01cd\3\2\2\2\u01d0Y\3\2\2\2\u01d1\u01d2\7\5\2\2\u01d2\u01d5"+
		"\5(\25\2\u01d3\u01d4\7K\2\2\u01d4\u01d6\5(\25\2\u01d5\u01d3\3\2\2\2\u01d5"+
		"\u01d6\3\2\2\2\u01d6\u01e0\3\2\2\2\u01d7\u01d8\7L\2\2\u01d8\u01dd\5\\"+
		"/\2\u01d9\u01da\7$\2\2\u01da\u01dc\5\\/\2\u01db\u01d9\3\2\2\2\u01dc\u01df"+
		"\3\2\2\2\u01dd\u01db\3\2\2\2\u01dd\u01de\3\2\2\2\u01de\u01e1\3\2\2\2\u01df"+
		"\u01dd\3\2\2\2\u01e0\u01d7\3\2\2\2\u01e0\u01e1\3\2\2\2\u01e1[\3\2\2\2"+
		"\u01e2\u01e3\5(\25\2\u01e3\u01e4\7#\2\2\u01e4\u01e6\3\2\2\2\u01e5\u01e2"+
		"\3\2\2\2\u01e5\u01e6\3\2\2\2\u01e6\u01e7\3\2\2\2\u01e7\u01e8\5(\25\2\u01e8"+
		"]\3\2\2\2\62ip\177\u008b\u0094\u0099\u00a1\u00a3\u00a8\u00af\u00b4\u00bb"+
		"\u00c1\u00c9\u00cb\u00db\u00de\u00e2\u00ec\u00f4\u00fc\u0100\u0109\u0113"+
		"\u0117\u011d\u0124\u012e\u0142\u014d\u0158\u015d\u0168\u016d\u0171\u0179"+
		"\u0182\u0185\u018d\u0196\u01a1\u01af\u01ba\u01cf\u01d5\u01dd\u01e0\u01e5";
	public static final ATN _ATN =
		new ATNDeserializer().deserialize(_serializedATN.toCharArray());
	static {
		_decisionToDFA = new DFA[_ATN.getNumberOfDecisions()];
		for (int i = 0; i < _ATN.getNumberOfDecisions(); i++) {
			_decisionToDFA[i] = new DFA(_ATN.getDecisionState(i), i);
		}
	}
}